"""Optional machine-learning stage (``pip install specimen[ml]``).

The core pipeline stays standard-library only. Everything under
``specimen.ml`` needs numpy / scikit-learn / LightGBM and is used for the
real-data models (EMBER static gate, CAPE behaviour family model) and the
benchmarks.
"""
