## probaduce

machine learning anomaly detection engine for network flow analysis. uses isolation forest and one-class svm to detect anomalous traffic patterns.

### install

```
pip install scikit-learn numpy
```

### usage

```
python3 probaduce.py demo                                      # synthetic data demo
python3 probaduce.py train -f flows.csv --model-type isolation_forest
python3 probaduce.py predict -f new_flows.csv -m model.pkl
python3 probaduce.py evaluate -f labeled_flows.json -m model.pkl
```

### options

- `command` : train, predict, evaluate, demo
- `-f` : flow data file (csv or json)
- `-m` : model file path (default: probaduce_model.pkl)
- `--model-type` : isolation_forest or one_class_svm
- `--contamination` : expected anomaly ratio (default: 0.05)
- `--json` : json output

### features extracted

- duration, byte counts, packet counts
- byte and packet ratios
- bytes per packet
- port entropy and unique destination ports
- average packet size

### detection patterns

- port scans (high port entropy, many unique destinations)
- data exfiltration (high src/dst byte ratio, long duration)
- c2 beaconing (regular intervals, symmetric byte counts)
