.PHONY: all run prog cleanall
SOURCES= ipk-sniffer.cpp my_string.cpp my_getnameinfo.cpp my_dns_cache.cpp ipk-sniffer.h my_string.h my_getnameinfo.h my_dns_cache.h my_arp.h

all: $(SOURCES)
	g++ -Wextra -Wall -pedantic -o ipk-sniffer ipk-sniffer.cpp my_string.cpp my_getnameinfo.cpp my_dns_cache.cpp -lpcap

ifeq (run,$(firstword $(MAKECMDGOALS)))
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  $(eval $(RUN_ARGS):;@:)
endif

run:
	sudo ./ipk-sniffer $(RUN_ARGS)

cleanall:
	rm  ipk-sniffer
