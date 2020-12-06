## sike

ml model evasion testing framework for validating anomaly detection robustness. generates adversarial traffic to test probaduce models.

### install

```
pip install scikit-learn numpy
```

### usage

```
python3 sike.py test -m probaduce_model.pkl --attack scan      # test scan evasion
python3 sike.py boundary -m model.pkl --feature 0              # find decision boundary
python3 sike.py perturb -m model.pkl --attack exfil            # targeted perturbation
python3 sike.py full -m model.pkl -n 100                       # test all attack types
```

### options

- `command` : test, boundary, perturb, full
- `-m` : probaduce model file (required)
- `--attack` : attack type (scan, exfil, c2)
- `--feature` : feature index for boundary search
- `-n` : test iterations

### evasion strategies

- blend: merge anomalous features toward normal distributions
- padding: add dummy traffic to normalize ratios
- split: distribute across multiple flows
- noise: gaussian perturbation of features

### safety

only operates on synthetic data against local models. no network traffic is generated.
