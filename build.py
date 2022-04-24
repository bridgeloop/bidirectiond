#!/usr/bin/env python3
semver = "0.1.5"
import sys, json, os, subprocess
if sys.argv[0] != "./build.py":
    print("shit")
    exit(1)
gcc_args = ["gcc", "-o", "bidirectiond"]
services_c = "#include <bddc/api.h>\n"
services = "struct bdd_service services[] = {"
names = [
	["bool %s(struct bdd_connections *connections, void *buf, size_t buf_size);", "serve"],
	["bool %s(struct bdd_connections *connections, const char *protocol_name, void *instance_info, bdd_io_id client_id, struct sockaddr client_sockaddr);", "connections_init"],
	["void %s(void *instance_info);", "instance_info_destructor"]]
np = 0
for dir, _, files in os.walk("src"):
    for file in files:
        if file[-2:] == ".c" or file[-2:] == ".o":
            gcc_args.append(os.path.join(dir, file))
        elif file == "service.json":
            np += 1
            path = os.path.join(dir, file)
            fd = open(path)
            p = json.loads(fd.read())
            services += "{ NULL, "
            for fn, member in names:
                services += f".{member}="
                if member in p:
                    name = p.get(member)
                    services_c += fn % name + "\n"
                    services += f"&({p.get(member)})"
                else:
                    services += "NULL"
                services += ","
            services_c += f"""bool {p["instantiate"]}(struct locked_hashmap *name_descriptions, struct bdd_service *service, size_t n_arguments, const char **arguments);\n"""
            supported_protocols = "NULL"
            if "supported_protocols" in p:
                supported_protocols = "(const char *[]){ %s, NULL, }" % json.dumps(p["supported_protocols"])[1:-1]
            services += """
				.instantiate = &(%s),
				.supported_arguments = (const char *[]){ %s, NULL, },
				.arguments_help = (char *)%s,
				.n_max_io = %i,
				.supported_protocols = %s,
			}""" % (p["instantiate"], json.dumps(p["supported_arguments"])[1:-1], json.dumps(p["arguments_help"]), p["n_max_io"], supported_protocols)
            fd.close()
services += "};"
services_c += services
fd = open("src/_services.c", "w")
fd.write(services_c)
fd.close()
gcc_args.append("src/_services.c")
sysname = os.uname().sysname
gcc_args.extend(["-lpthread", "-lssl", "-lcrypto", "-Iinc", "-DN_SERVICES=" + str(np), "-DPROG_SEMVER=" + json.dumps(semver), "-funsigned-char"] + sys.argv[1:])
subprocess.call(gcc_args)
os.unlink("src/_services.c")
