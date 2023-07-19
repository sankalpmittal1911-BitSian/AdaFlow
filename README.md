# AdaFlow
An In-Network cache that is implemented in the data plane for intrusion detection of flow-based attacks. 

## About this repository:
``Control Plane``: contains control plane logic to initialize AdaFlow cache at the very beginning. 

``Data Plane``: contains 4 prototypes to handle attacks based on packet length and IPD distributions, and based on CIC-IDS2017 dataset. Also, it contains Strawman version of Push and Pull Designs. 

``ML Models``: contains 3 types of ML models generated to be deployed on the data plane - Single ML Model, Sequential Multiphase ML Model and Aggregated Multiphase ML Models. All these models are Tree-Based. 

``Remote Server``: contains ``profiler`` to derive configurations for various training dataset. Also contains a complex ML classifier to classify flows in the server. 

``Simulations``: contains simulations of AdaFlow, NetBeacon and *Flow. 
