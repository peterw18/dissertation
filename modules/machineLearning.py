from sentence_transformers import SentenceTransformer
from transformers import logging
import torch
import pandas as pd
from sklearn.ensemble import IsolationForest
from river import anomaly
import time
import logging as lg
import os

os.environ['HF_HUB_VERBOSITY'] = 'error'
os.environ['TRANSFORMERS_VERBOSITY'] = 'error'
os.environ['TRANSFORMERS_NO_ADVISORY_WARNINGS'] = '1'

logging.set_verbosity_error()

device = 'cuda' if torch.cuda.is_available() else 'cpu'
sbert_model_name = 'sentence-transformers/all-MiniLM-L6-v2'
sbert = SentenceTransformer(sbert_model_name)

def encodeSentences(sentences:list, normalize:bool=True) -> list:
    """
    Returns a list of vectors representing a sentence, according to a pretrained model.
    """
    return sbert.encode(sentences, normalize_embeddings=normalize).tolist()

def createIsolationForest(contamination:float=0.001) -> IsolationForest:
    """
    Create an Isolation Forest model trained on the events given.
    """
    model = IsolationForest(
        n_estimators=200,
        max_samples=256,
        contamination=contamination,
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1
    )
    return model

def getIsolationForestPredictions(events:pd.DataFrame, model:IsolationForest=None) -> pd.DataFrame:
    """
    Use an Isolation Forest model to predict whether a record is anomalous or not
    """
    if model is None:
        model = createIsolationForest(events)

    events['anomalous'] = model.fit_predict(events.drop(columns=['System.EventRecordID']))
    events['raw_ano_score'] = model.decision_function(events.drop(columns=['anomalous', 'System.EventRecordID']))

    return events

def createHalfSpaceTrees(baselineEvents:pd.DataFrame, logger:lg.Logger) -> anomaly.HalfSpaceTrees:
    """
    Create a Half Space Trees model trained on the events given.
    """
    model = anomaly.HalfSpaceTrees(
        n_trees=60,
        height=3,
        window_size=5000, # could be up to 100000 and do entire logs?
        limits={col: [0,1] for col in baselineEvents.columns},
        seed=None
    )

    timeBefore = time.time()

    for row in baselineEvents.drop(columns=['System.EventRecordID']).to_dict(orient='records'):
        model.learn_one(row) # training

    logger.info(f"HST model took {round(time.time() - timeBefore, 1)} seconds to train.")
    
    return model

def getHSTPredictions(events:pd.DataFrame, model:anomaly.HalfSpaceTrees, logger:lg.Logger) -> pd.DataFrame:
    """
    Use a Half Space Tree model to predict whether a record is anomalous or not
    """

    timeBefore = time.time()
    
    scores = []
    for row in events.drop(columns=['System.EventRecordID']).to_dict(orient='records'):
        scores.append(model.score_one(row))
        model.learn_one(row)

    events = events.copy()

    events['anomalous'] = scores

    logger.info(f"HST model predicted {events.shape[0]} anomalous scores, in {round(time.time() - timeBefore, 1)} seconds.")

    return events