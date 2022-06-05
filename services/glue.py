#!/usr/bin/env python3
import sys, json, os, tempfile, subprocess, glob

dir_path = os.path.dirname(__file__)

declarations = ""
services = "const struct bdd_service services[] = {"
n_services = 0
def append_service(service):
	global declarations, services, n_services
	service_str = "{"
	key, value = None, None
	#
	key = "conversation_init"
	if key in service:
		value = service[key]
		if type(value) != str:
			raise Exception("error")
		declarations += f"bool {value}(struct bdd_conversation *conversation, const char *protocol_name, const void *instance_info, uint8_t client_id, struct sockaddr client_sockaddr);"
	else:
		value = "NULL"
	service_str += f".{key} = &({value}),"
	#
	key = "instance_info_destructor"
	if key in service:
		value = service[key]
		if type(value) != str:
			raise Exception("error")
		declarations += f"void {value}(void *instance_info);"
	else:
		value = "NULL"
	service_str += f".{key} = &({value}),"
	#
	key = "instantiate"
	value = service[key]
	if type(value) != str:
		raise Exception("error")
	declarations += f"bool {value}(struct bdd_name_descs *name_descs, const struct bdd_service *service, size_t n_arguments, const char **arguments);"
	service_str += f".{key} = &({value}),"
	#
	key = "handle_events"
	value = service[key]
	if type(value) != str:
		raise Exception("error")
	declarations += f"void {value}(struct bdd_conversation *conversation);"
	service_str += f".{key} = &({value}),"
	#
	key = "supported_protocols"
	if key in service:
		if type(service[key]) != list:
			raise Exception("error")
		value = "(const char *[]){"
		for entry in service[key]:
			if type(entry) != str:
				raise Exception("error")
			value += json.dumps(entry)
			value += ","
		value += "NULL}"
	else:
		value = "NULL"
	service_str += f".{key} = {value},"
	#
	key = "supported_arguments"
	if type(service[key]) != list:
		raise Exception("error")
	value = "(const char *[]){"
	for entry in service[key]:
		if type(entry) != str:
			raise Exception("error")
		value += json.dumps(entry)
		value += ","
	value += "NULL}"
	service_str += f".{key} = {value},"
	#
	key = "arguments_help"
	value = json.dumps(service[key])
	if type(value) != str:
		raise Exception("error")
	service_str += f".{key} = (char *){value},"
	#
	service_str += "},"
	services += service_str
	n_services += 1

for path in glob.glob(os.path.join(dir_path, "*/service.json")):
	fd = open(path)
	append_service(json.load(fd))
	fd.close()

services += "};const size_t n_services = " + str(n_services) + ";"

fd = tempfile.NamedTemporaryFile(delete=False, suffix=".c")
fd.write(b"#include <bdd-core/settings.h>\n" + bytes(declarations, "ascii") + bytes(services, "ascii"))
fd.close()
subprocess.run([
	"gcc",

	"-c", fd.name,
	"-o", os.path.join(dir_path, "..", "output", "glue.o"),

	"-I" + os.path.join(dir_path, "..", "inc"),
])
os.unlink(fd.name)
