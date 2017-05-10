Instructions on how to run the state synchronization tests
####

State Sync currently implements five messages. The tests for each message are based on the exisitng MAC Learning application.

To run the examples:
- run ryu controller:
  cd <ryu folder>
  PYTHONPATH=. bin/ryu-manager ryu/app/beba/state_sync/<example file>
  
1.  get_flow_state.py
    Asks for state of a flow and parses the response.

2.  get_flows_in_state.py
    Asks for the flow(s) in a state and parses the response.

3.  get_global_state.py
    Asks for the global state of a switch and parses the response.

4.  state_change_notification.py
    Applies a state change and parses the notification for this state change as sent by the switch.
    The Message contains:
    - Table ID
    - Old state
    - New state
    - Key

5.  flow_mod_notification.py
    Sends a flow modification and parses the notifications for this flow_mod message as sent by the switch.
    The Message contains:
    - Table ID
    - Match key
    - Number of instructions
    - Implemented instructions (actions are not packed in the notification)

6.  get_global_data_vars.py
    Asks for the global data vars from table 0 of a switch and parses the response.
    For each packet forwarded by the the switch the global_data_var 0 gets incremented by 1.

- run mininet:
  sudo mn --topo single,4 --mac --switch user --controller remote
