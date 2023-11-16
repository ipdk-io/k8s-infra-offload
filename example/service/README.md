## Details
This directory includes a service manifest file and a script to run the tests.
- iperf_tcp.yaml 
    - This file has the manifests to create an iperf server and a client. 
    - The iperf server is started as a service with two backend endpoints and
      the iperf client is started as a daemonset.
- run.sh
    - Script to run the test. The script sends 100 client requests to the iperf server.
- clean_up.sh
    - Script to delete the server and client pods.

## How to Run
- Create the iperf server and client   
  - # kubectl create -f iperf_tcp.yaml
- Run the tests
  - # ./run.sh <client-pod-name>
- Delete iperf server and client pods
  - # ./clean_up.sh
