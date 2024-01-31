from flask import Flask, request, jsonify
import numpy as np
import pandas as pd
import joblib

app = Flask(__name__)

attacks_f = {"Bot": ["Bwd Packet Length Mean", "Flow IAT Max", "Flow Duration", "Flow IAT Min", "Label"],
             "DDoS": ["Bwd Packet Length Std", "Total Backward Packets", "Fwd IAT Total", "Flow Duration", "Label"],
             "DoS GoldenEye": ["Flow IAT Max", "Bwd Packet Length Std", "Flow IAT Min", "Total Backward Packets",
                               "Label"],
             "DoS Hulk": ["Bwd Packet Length Std", "Fwd Packet Length Std", "Fwd Packet Length Max", "Flow IAT Min",
                          "Label"],
             "DoS Slowhttptest": ["Flow IAT Mean", "Fwd Packet Length Min", "Bwd Packet Length Mean",
                                  "Total Length of Bwd Packets", "Label"],
             "DoS slowloris": ["Flow IAT Mean", "Total Length of Bwd Packets", "Bwd Packet Length Mean",
                               "Total Fwd Packets", "Label"],
             "FTP-Patator": ["Fwd Packet Length Max", "Fwd Packet Length Std", "Fwd Packet Length Mean",
                             "Bwd Packet Length Std", "Label"],
             "Heartbleed": ["Total Backward Packets", "Fwd Packet Length Max", "Flow IAT Min", "Bwd Packet Length Max",
                            "Label"],
             "Infiltration": ["Fwd Packet Length Max", "Fwd Packet Length Mean", "Flow Duration",
                              "Total Length of Fwd Packets", "Label"],
             "PortScan": ["Flow Bytes/s", "Total Length of Fwd Packets", "Fwd IAT Total", "Flow Duration", "Label"],
             "SSH-Patator": ["Fwd Packet Length Max", "Flow Duration", "Flow IAT Max", "Total Length of Fwd Packets",
                             "Label"],
             "Web Attack": ["Bwd Packet Length Std", "Total Length of Fwd Packets", "Flow Bytes/s", "Flow IAT Max",
                            "Label"]}

algorithms = ['AdaBoost', 'Nearest Neighbors', 'Random Forest']


@app.route('/', methods=['POST'])
def process_data():
    try:
        data = request.json
        try:
            df = pd.DataFrame(data)
            df.replace([np.inf, -np.inf], 0, inplace=True)
            df.fillna(0, inplace=True)
            column_name_changes = {
                'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
                'Bwd Pkt Len Std': 'Bwd Packet Length Std',
                'Fwd IAT Tot': 'Fwd IAT Total',
                'Tot Bwd Pkts': 'Total Backward Packets',
                'Fwd Pkt Len Std': 'Fwd Packet Length Std',
                'Fwd Pkt Len Max': 'Fwd Packet Length Max',
                'Fwd Pkt Len Min': 'Fwd Packet Length Min',
                'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
                'Tot Fwd Pkts': 'Total Fwd Packets',
                'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
                "Bwd Pkt Len Max": 'Bwd Packet Length Max',
                "TotLen Fwd Pkts": 'Total Length of Fwd Packets',
                "Flow Byts/s": 'Flow Bytes/s'
            }
            df.rename(columns=column_name_changes, inplace=True)
            results = []
            final = "After analysing all the results, our application's prediction : Safe [0% Danger]"
            max = 0
            for attack in attacks_f:
                for alg in algorithms:
                    model = joblib.load(f"models\{alg}\{alg}_{attack}.pkl")
                    df1 = df[attacks_f[attack][0:-1]]
                    t_output = model.predict_proba(df1)
                    t_output = t_output[:, 0] * 100
                    print(t_output)
                    c = 0
                    for i in t_output:
                        if i > 50:
                            c += 1
                    results.append([f"{alg} shows", (c * 100 / len(t_output)), f"% chance of {attack}."])
                    if max < (c * 100 / len(t_output)):
                        max = c * 100 / len(t_output)
                        final = f"After analysing all the results, our application's prediction :\n{max}% chance of {attack}"
            results.append(final)
            return results
        except Exception as e:
            print(e)
            return [["here", "here", "0", "0"]]
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=500)
