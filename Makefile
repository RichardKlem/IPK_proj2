.PHONY: run
PCAP=/usr/include/pcap/

main: main.cpp
	g++ -I$PCAP -o main main.cpp -lpcap

proj: proj.cpp
	g++ -I$PCAP -o proj proj.cpp -lpcap

ifeq (run,$(firstword $(MAKECMDGOALS)))
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

prog:
	sudo ./proj $(RUN_ARGS)

run : prog
	@echo prog $(RUN_ARGS)

cleanall:
	rm main proj
