.PHONY: all compile clean test dialyzer typer

REBAR ?= rebar3

all: compile

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

test: compile
	@$(REBAR) ct

dialyzer:
	@$(REBAR) dialyzer

typer:
	@typer \
		-pa _build/default/lib/ewpcap/ebin \
		-I include \
		--plt _build/default/*_plt \
		-r ./src
