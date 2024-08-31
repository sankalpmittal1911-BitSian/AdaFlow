# AdaFlow
An In-Network cache that is implemented in the data plane for intrusion detection of flow-based attacks. 
![image](https://github.com/networked-systems-iith/AdaFlow/assets/104780009/4d890f5f-ba71-496a-922b-26163c863aa3)


## Published in IFIP Networking conference, 2024

## About this repository
``Control Plane``: contains control plane logic to initialize AdaFlow cache at the very beginning. 

``Data Plane``: contains 4 prototypes to handle attacks based on packet length and IPD distributions, and based on CIC-IDS2017 dataset. Also, it contains Strawman version of Push and Pull Designs. 

``ML Models``: contains 3 types of ML models generated to be deployed on the data plane - Single ML Model, Sequential Multiphase ML Model and Aggregated Multiphase ML Models. All these models are Tree-Based. 

``Remote Server``: contains ``profiler`` to derive configurations for various training dataset. Also contains a complex ML classifier to classify flows in the server. 

``Simulations``: contains simulations of AdaFlow, NetBeacon and *Flow. 

## General Dependencies
1. Make sure you have Tofino 2 and Tofino 1 models/hardware running. Follow this [tutorial](https://docs.google.com/document/d/1gyYWL0HY2SanzAoA6GGRImf9ERR1KXrG0Ngg8Zh5VfA/edit#). 
2. Make sure you have basic python3 libraries like ``sklearn`` and ``hyperopt`` up and running. 

## Using this repository
1. Collect required PCAP traces in the ``Dataset`` folder.
2. Obtain trained ML classifier from ``Remote Server/classifier.py``.
3. Obtained pruned feature set and optimal ``bin width`` from  ``Remote Server/profiler.py``.
4. On this obtained configuration, train Aggregated Multiphase ML Model (make sure it is the same type as a remote classifier), ``ML Models/agg_model.py``.
5. Initialize AdaFlow Cache with this ``agg_model.pkl`` using ``Control Plane/controller.py``.
6. Connect a Tofino Switch to two (preferably) linux servers.
7. Run the prototype given in ``Data Plane`` folder. 
8. Send traffic to the switch (or PCAP traces in test set using ``tcpreplay``).
9. Obtain the output packets on another server and process the packets to obtain flow features, or directly check classification results obtain on data plane.
10. That is it!

## For obtaining results in paper?
Please go to ``For AEC`` folder and follow the instructions there!

## Note
The repository is still incomplete!

## Citing
If you wish to cite our paper, please use:
```
S. Mittal, H. Kotha, M. Anand Krishna and P. Tammana, "AdaFlow: Efficient In-Network Traffic Classification using Programmable Switches," 2024 IFIP Networking Conference (IFIP Networking), Thessaloniki, Greece, 2024, pp. 258-266, doi: 10.23919/IFIPNetworking62109.2024.10619766. keywords: {Accuracy;Costs;Memory management;Prototypes;Security},
```
