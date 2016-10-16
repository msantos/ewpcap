REBAR ?= rebar3

all: compile

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

test: compile
	@$(REBAR) ct1

.PHONY: test dialyzer typer clean

dialyzer:
	@$(REBAR) dialyzer

typer:
	@typer -pa _build/default/lib/ewpcap/ebin -I include --plt _build/default/*_plt -r ./src
