# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2019 Red Hat Inc.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import os
import uuid

from ansible.module_utils.six import iteritems
from ansible.module_utils.six import iterkeys
from ansible.module_utils._text import to_text
from ansible.module_utils.basic import env_fallback

try:
    from skydive.graph import Node, Edge
    from skydive.rest.client import RESTClient

    HAS_SKYDIVE_CLIENT = True
except ImportError:
    HAS_SKYDIVE_CLIENT = False

# defining skydive constants
SKYDIVE_GREMLIN_QUERY = "G.V().Has"
SKYDIVE_GREMLIN_EDGE_QUERY = "G.E().Has"

SKYDIVE_PROVIDER_SPEC = {
    "endpoint": dict(fallback=(env_fallback, ["SKYDIVE_ENDPOINT"])),
    "username": dict(fallback=(env_fallback, ["SKYDIVE_USERNAME"])),
    "password": dict(
        fallback=(env_fallback, ["SKYDIVE_PASSWORD"]), no_log=True
    ),
    "insecure": dict(
        type="bool",
        default=False,
        fallback=(env_fallback, ["SKYDIVE_INSECURE"]),
    ),
    "ssl": dict(
        type="bool", default=False, fallback=(env_fallback, ["SKYDIVE_SSL"])
    ),
}


class skydive_client_check(object):
    """ Base class for implementing Skydive Rest API """

    provider_spec = {
        "provider": dict(type="dict", options=SKYDIVE_PROVIDER_SPEC)
    }

    def __init__(self, **kwargs):
        """ Base class for implementing Skydive Rest API """
        if not HAS_SKYDIVE_CLIENT:
            raise Exception(
                "skydive-client is required but does not appear "
                "to be installed.  It can be installed using the "
                "command `pip install skydive-client`"
            )

        if not set(kwargs.keys()).issubset(SKYDIVE_PROVIDER_SPEC.keys()):
            raise Exception(
                "invalid or unsupported keyword argument for skydive_restclient connection."
            )
        for key, value in iteritems(SKYDIVE_PROVIDER_SPEC):
            if key not in kwargs:
                # apply default values from SKYDIVE_PROVIDER_SPEC since we cannot just
                # assume the provider values are coming from AnsibleModule
                if "default" in value:
                    kwargs[key] = value["default"]
                # override any values with env variables unless they were
                # explicitly set
                env = ("SKYDIVE_%s" % key).upper()
                if env in os.environ:
                    kwargs[key] = os.environ.get(env)


class skydive_restclient(skydive_client_check):
    """ Base class for implementing Skydive Rest API """

    def __init__(self, **kwargs):
        super(skydive_restclient, self).__init__(**kwargs)
        kwargs["scheme"] = "http"
        if "ssl" in kwargs:
            if kwargs["ssl"]:
                kwargs["scheme"] = "https"
        if "insecure" not in kwargs:
            kwargs["insecure"] = False
        self.restclient_object = RESTClient(
            kwargs["endpoint"],
            scheme=kwargs["scheme"],
            insecure=kwargs["insecure"],
            username=kwargs["username"],
            password=kwargs["password"],
        )

    def get_node_id(self, node_selector):
        """ Checks if Gremlin expresssion is passed as input to get the nodes UUID """
        if node_selector.startswith("G.") or node_selector.startswith("g."):
            nodes = self.restclient_object.lookup_nodes(node_selector)
            if len(nodes) == 0:
                raise self.module.fail_json(
                    msg=to_text("Node not found: {0}".format(node_selector))
                )
            elif len(nodes) > 1:
                raise self.module.fail_json(
                    msg=to_text(
                        "Node selection should return only one node: {0}".format(
                            node_selector
                        )
                    )
                )
            return str(nodes[0].id)
        return node_selector


class skydive_lookup(skydive_restclient):
    """ Implements Skydive Lookup queries """

    provider_spec = {
        "provider": dict(type="dict", options=SKYDIVE_PROVIDER_SPEC)
    }

    def __init__(self, provider):
        super(skydive_lookup, self).__init__(**provider)
        self.query_str = ""

    def lookup_query(self, filter_data):
        query_key = filter_data.keys()[0]
        self.query_str = filter_data[query_key]
        nodes = self.restclient_object.lookup_nodes(self.query_str)
        result = []
        for each in nodes:
            result.append(each.__dict__)
        if len(result) == 0:
            raise Exception(
                "Cannot find any entry for the input Gremlin query!"
            )
        return result


class skydive_flow_capture(skydive_restclient):
    """ Implements Skydive Flow capture modules """

    def __init__(self, module):
        self.module = module
        provider = module.params["provider"]

        super(skydive_flow_capture, self).__init__(**provider)

    def run(self, ib_spec):
        state = self.module.params["state"]
        if state not in ("present", "absent"):
            self.module.fail_json(
                msg="state must be one of `present`, `absent`, got `%s`"
                % state
            )

        result = {"changed": False}
        obj_filter = dict(
            [
                (k, self.module.params[k])
                for k, v in iteritems(ib_spec)
                if v.get("ib_req")
            ]
        )

        proposed_object = {}
        for key in iterkeys(ib_spec):
            if self.module.params[key] is not None:
                proposed_object[key] = self.module.params[key]

        if obj_filter["query"]:
            cature_query = obj_filter["query"]
        elif obj_filter["interface_name"] and obj_filter["type"]:
            cature_query = (
                SKYDIVE_GREMLIN_QUERY
                + "('Name', '{0}', 'Type', '{1}')".format(
                    obj_filter["interface_name"], obj_filter["type"]
                )
            )
        else:
            raise self.module.fail_json(
                msg="Interface name and Type is required if gremlin query is not defined!"
            )

        # to check current object ref for idempotency
        captured_list_objs = self.restclient_object.capture_list()
        current_ref_uuid = None
        for each_capture in captured_list_objs:
            if cature_query == each_capture.__dict__["query"]:
                current_ref_uuid = each_capture.__dict__["uuid"]
                break
        if state == "present":
            if not current_ref_uuid:
                try:
                    self.restclient_object.capture_create(
                        cature_query,
                        obj_filter["capture_name"],
                        obj_filter["description"],
                        obj_filter["extra_tcp_metric"],
                        obj_filter["ip_defrag"],
                        obj_filter["reassemble_tcp"],
                        obj_filter["layer_key_mode"],
                    )
                except Exception as e:
                    self.module.fail_json(msg=to_text(e))
                result["changed"] = True
        if state == "absent":
            if current_ref_uuid:
                try:
                    self.restclient_object.capture_delete(current_ref_uuid)
                except Exception as e:
                    self.module.fail_json(msg=to_text(e))
                result["changed"] = True

        return result


class skydive_node(skydive_restclient):
    """ Implements Skydive Node modules """

    def __init__(self, module):
        self.module = module
        provider = module.params["provider"]
        super(skydive_node, self).__init__(**provider)

    def run(self):
        result = {"changed": False}

        try:
            node = None

            node_query = (
                SKYDIVE_GREMLIN_QUERY
                + "('Name', '{0}', 'Type', '{1}')".format(
                    self.module.params["name"], self.module.params["node_type"]
                )
            )

            # Get the matching node
            query_result = self.restclient_object.lookup_nodes(node_query)
            if query_result:
                node = query_result[0]

            if not node and self.module.params["state"] == "present":
                # Create node
                seed = self.module.params["seed"]
                if not seed:
                    seed = "%s:%s" % (self.module.params["name"], self.module.params["node_type"])

                node_id = str(uuid.uuid5(uuid.NAMESPACE_OID, seed))

                metadata = self.module._check_type_dict(self.module.params["metadata"])
                metadata["Name"] = self.module.params["name"]
                metadata["Type"] = self.module.params["node_type"]

                result = self.restclient_object.node_create(
                            node_id=node_id,
                            host=self.module.params["host"],
                            metadata=metadata,
                         ).repr_json()

                result["changed"] = True

            elif node and self.module.params["state"] == "present":
                # Update existing node
                # Check if defined metadata is equal to the existing node
                metadata = self.module._check_type_dict(self.module.params["metadata"])

                if "TID" in metadata or "Type" in metadata or "Name" in metadata:
                    self.module.fail_json(msg="Metadata values 'TID', 'Type' and 'Name' could not be changed")

                # Create a JSON patch for each of the keys defined, if it is different from the one already stored
                patches = []
                for key, value in iteritems(metadata):
                    if value != node.metadata.get(key):
                        patches.append({
                            "path": "/Metadata/{}".format(key),
                            "value": value,
                            "op": "replace" if key in node.metadata else "add",
                        })

                # Only execute patching if we have something to modify
                if patches:
                    result = self.restclient_object.node_update(node_id=node.id, patches=patches).repr_json()
                    result["changed"] = True

            elif node and self.module.params["state"] == "absent":
                # Delete node
                result["response"] = self.restclient_object.node_delete(node.id)
                result["changed"] = True

        except Exception as e:
            self.module.fail_json(msg=to_text(e))

        return result


class skydive_edge(skydive_restclient):
    """ Implements Skydive Edge modules """

    def __init__(self, module):
        self.module = module
        provider = module.params["provider"]
        super(skydive_edge, self).__init__(**provider)

    def run(self):
        result = {"changed": False}

        try:
            edge = None

            parent_node_id = self.get_node_id(self.module.params["parent_node"])
            child_node_id = self.get_node_id(self.module.params["child_node"])

            edge_query = (
                SKYDIVE_GREMLIN_EDGE_QUERY
                + "('Parent', '{0}', 'Child', '{1}')".format(parent_node_id, child_node_id)
            )

            # Get the first edge between the nodes specified
            query_result = self.restclient_object.lookup_edges(edge_query)
            if query_result:
                edge = query_result[0]

            if not edge and self.module.params["state"] == "present":
                # Create edge
                seed = self.module.params["seed"]
                if not seed:
                    seed = "%s:%s:%s" % (
                               self.module.params["parent_node"],
                               self.module.params["child_node"],
                               self.module.params["relation_type"],
                           )

                edge_id = str(uuid.uuid5(uuid.NAMESPACE_OID, seed))

                metadata = self.module._check_type_dict(self.module.params["metadata"])
                metadata["RelationType"] = self.module.params["relation_type"]

                result = self.restclient_object.edge_create(
                            parent_node_id,
                            child_node_id,
                            edge_id=edge_id,
                            host=self.module.params["host"],
                            metadata=metadata,
                         ).repr_json()

                result["changed"] = True

            elif edge and self.module.params["state"] == "present":
                # Update first edge found between nodes
                metadata = self.module._check_type_dict(self.module.params["metadata"])
                metadata["RelationType"] = self.module.params["relation_type"]

                # Create a JSON patch for each of the keys defined, if it is different from the one already stored
                patches = []
                for key, value in iteritems(metadata):
                    if value != edge.metadata.get(key):
                        patches.append({
                            "path": "/Metadata/{}".format(key),
                            "value": value,
                            "op": "replace" if key in edge.metadata else "add",
                        })

                # Only execute patching if we have something to modify
                if patches:
                    result = self.restclient_object.edge_update(edge_id=edge.id, patches=patches).repr_json()
                    result["changed"] = True

            elif edge and self.module.params["state"] == "absent":
                # Delete edge
                result["response"] = self.restclient_object.edge_delete(edge.id)
                result["changed"] = True

        except Exception as e:
            self.module.fail_json(msg=to_text(e))

        return result
