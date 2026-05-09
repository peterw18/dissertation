import matplotlib.pyplot as plt
import seaborn as sns
import logging as lg

def plotHist(events, feature, name):
    plt.figure(figsize=(10, 6))
    sns.histplot(data=events, x=feature, element='step', common_norm=False, kde=True)

    plt.xlabel(f"Calculated Anomaly Score: {feature}", fontsize=12)
    plt.ylabel("Frequency", fontsize=12)
    plt.title("Distribution of Anomaly Score")

    plt.grid(True, alpha=0.3)

    plt.savefig(f'.\\figures\\{name}.png')

def getAnomalousStatsIF(events, logger:lg.Logger):
    anomalousEvents = events.query('raw_ano_score <= 0')

    logger.debug(f"""
********************************
*** Anomaly Detection: Stats ***
********************************

[-] Count:\t{anomalousEvents.shape[0]}
[-] Mean:\t{anomalousEvents['raw_ano_score'].mean()}
[-] Minimum:\t{anomalousEvents['raw_ano_score'].min()}
[-] Maximum:\t{anomalousEvents['raw_ano_score'].max()}
    """)    