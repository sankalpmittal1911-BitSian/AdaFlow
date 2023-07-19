**Descriptions of different P4 prototypes**

1. **Prototype 1:** Detect covert channels attacks, P2P Application Botnets and DDoS attacks. In general, it can be used to detect _any_ attacks that use packet lengths and IPD distributions as the flow features.
2. **Prototype 2:** Detect FTP and SSH Patator attacks, and Portscans and BotNets.
3. **Prototype 3:** Detect "Infiltration" and Web-attacks.
4. **Prototype 4:** Detect DoS and Heartbleed attacks.
5. ``Strawman_pull`` is the prototype for Strawman Solution using Pull-Based Design.
6. ``Strawman_push`` is the prototype for Strawman Solution using Push-Based Design.

In the ``Task_specific`` folder, we have cut-down prototypes to separately detect covert channel attacks, P2P botnet detection, DDoS attacks.

_Note_: To compile any prototype, run ``p4build.sh`` after putting the paths appropriately. 
