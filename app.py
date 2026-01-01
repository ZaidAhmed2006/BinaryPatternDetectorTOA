from automata.fa.nfa import NFA
from automata.fa.dfa import DFA


#--------RULE DEFINITIONS (REGEX BASED)-------
rules = {
    1: ("Every 1 is followed by 0", "(0|10)*"),
    2: ("Even length binary string", "(00|01|10|11)*"),
    3: ("Odd length binary string", "(0|1)((00|01|10|11)*)"),
    4: ("Exactly two 0s", "1*01*01*"),
    5: ("Length divisible by 3", "((0|1){3})*"),
    6: ("Even number of 0s", "(1*01*01*)*"),
    7: ("At least two 0s", "(0|1)*0(0|1)*0(0|1)*"),
    8: ("At most two 0s", "1*|1*01*|1*01*01*"),
    9: ("Starts with 0", "0(0|1)*"),
    10: ("Ends with 0", "(0|1)*0"),
    11: ("Contains substring 01", "(0|1)*01(0|1)*"),
    12: ("Contains substring 00", "(0|1)*00(0|1)*"),
    13: ("Ends with 11", "(0|1)*11"),
    14: ("Starts with 1", "1(0|1)*"),
    15: ("Contains both 0 and 1",
         "(0|1)*0(0|1)*1(0|1)*|(0|1)*1(0|1)*0(0|1)*")
}


#----BUILD DFA FROM REGEX-----
def build_dfa(regex: str) -> DFA:
    nfa = NFA.from_regex(regex)
    dfa = DFA.from_nfa(nfa)
    return dfa


#------MAKE DFA TOTAL (ADD DEAD STATE)-----
def make_dfa_total(dfa: DFA) -> DFA:
    dead = "DEAD"

    states = set(dfa.states)
    states.add(dead)

    transitions = {s: dict(dfa.transitions.get(s, {})) for s in dfa.states}
    transitions[dead] = {}

    for state in states:
        transitions.setdefault(state, {})
        for sym in dfa.input_symbols:
            if sym not in transitions[state]:
                transitions[state][sym] = dead

    for sym in dfa.input_symbols:
        transitions[dead][sym] = dead

    return DFA(
        states=states,
        input_symbols=dfa.input_symbols,
        transitions=transitions,
        initial_state=dfa.initial_state,
        final_states=set(dfa.final_states),
    )


#-----RENAME STATES TO q0, q1, ...
def relabel_states(dfa: DFA):
    ordered_states = sorted(dfa.states, key=str)
    mapping = {s: f"q{i}" for i, s in enumerate(ordered_states)}

    new_transitions = {}
    for s, trans in dfa.transitions.items():
        new_transitions[mapping[s]] = {
            sym: mapping[dest] for sym, dest in trans.items()
        }

    new_dfa = DFA(
        states=set(mapping.values()),
        input_symbols=dfa.input_symbols,
        transitions=new_transitions,
        initial_state=mapping[dfa.initial_state],
        final_states={mapping[s] for s in dfa.final_states},
    )
    return new_dfa


#-------TRANSITION TRACE------
def show_transition_trace(dfa: DFA, binary: str):
    current = dfa.initial_state

    print("\nTransition Trace:")
    print(f"Initial State: {current}")

    for symbol in binary:
        next_state = dfa.transitions[current][symbol]
        print(f"{current} --{symbol}--> {next_state}")
        current = next_state

    print(f"Final State: {current}")
    return current



#--------INPUT VALIDATION--------
def normalize_input(binary: str):
    return binary if binary and all(c in "01" for c in binary) else None


#----- MAIN PROGRAM---
if __name__ == "__main__":

    print("\n===============================================")
    print("     BINARY STRING PATTERN DETECTOR USING DFA")
    print("===============================================\n")

    while True:
        print("\nAvailable Rules:\n")
        for k, v in rules.items():
            print(f"{k}. {v[0]}")
        print("0. Exit")

        try:
            choice = int(input("\nSelect rule number: "))
        except ValueError:
            print("Invalid input!")
            continue

        if choice == 0:
            print("\nProgram Terminated.")
            break

        if choice not in rules:
            print("Invalid rule number!")
            continue

        rule_name, regex = rules[choice]
        print(f"\nSelected Rule: {rule_name}")

        binary = normalize_input(input("Enter binary string (0,1): "))
        if binary is None:
            print("Invalid input!")
            continue

        dfa = build_dfa(regex)
        dfa = make_dfa_total(dfa)
        dfa = relabel_states(dfa)

        final_state = show_transition_trace(dfa, binary)

        if final_state in dfa.final_states:
            print("\nRESULT: STRING ACCEPTED")
        else:
            print("\nRESULT: STRING REJECTED")