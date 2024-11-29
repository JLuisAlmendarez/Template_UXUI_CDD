from flask import Flask, request, jsonify
import pandas as pd
import logging
import requests
import os
import dagshub
import mlflow
import json
from dagshub.auth import add_app_token

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

with open("dagshub_token.json", "r") as f:
    config = json.load(f)
    print(config)

add_app_token(config['token'])

os.environ['MLFLOW_TRACKING_USERNAME'] = "Almendarez02"  # Tu usuario de DagsHub
os.environ['MLFLOW_TRACKING_PASSWORD'] = config['token']

dagshub.init(url="https://dagshub.com/PacoTinoco/Proyecto_Final_CDD", mlflow=True)
MLFLOW_TRACKING_URI = mlflow.get_tracking_uri()

MODEL_NAME = "amazon-stock-model-randomforest-prefect"
MODEL_ALIAS = "champion"
MODEL_URI = f"models:/{MODEL_NAME}@{MODEL_ALIAS}"

def load_model():
    """Carga el modelo desde MLflow"""
    try:
        return mlflow.pyfunc.load_model(MODEL_URI)
    except Exception as e:
        logger.error(f"Error al cargar el modelo: {e}")
        raise RuntimeError("No se pudo cargar el modelo")

def calcular_prediccion(model, input_data, capital_inicial, dias_inversion):
    try:
        precio_inicial = float(input_data['Open'].iloc[-1])
        precio_estimado = float(model.predict(input_data)[0])  # Extraer el primer elemento
        
        # Calcular precio final usando la proporción de cambio estimada
        precio_siguiente = precio_inicial
        for _ in range(dias_inversion):
            proporcion = precio_estimado / precio_inicial
            precio_siguiente = precio_siguiente * proporcion
        
        # Calcular retorno de inversión
        cantidad_acciones = capital_inicial / precio_inicial
        capital_final = float(cantidad_acciones * precio_siguiente)
        
        return {
            'capital_final': capital_final,
            'retorno_porcentual': float((capital_final - capital_inicial) / capital_inicial * 100)
        }
    except Exception as e:
        logger.error(f"Error en el cálculo de predicción: {e}")
        raise RuntimeError("Error al calcular la predicción")
    
    

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({'status': 'ML Models API is running'})

def send_results_to_orchestrator(predictions):
    try:
        url = "http://orchestrator:5012/results"
        data = {"predictions": predictions}

        response = requests.post(url, json=data)

        if response.status_code == 200:
            logger.info("Resultados enviados al orquestador correctamente.")
        else:
            logger.warning(f"El orquestador respondió con código: {response.status_code}")
            
    except Exception as e:
        logger.warning(f"No se pudieron enviar los resultados al orquestador: {e}")

@app.route('/<model_type>/predict', methods=['POST'])
def predict(model_type):
    try:
        # Validar tipo de modelo
        if model_type not in ['amazon', 'google']:
            return jsonify({'error': 'Invalid model type'}), 400
            
        # Obtener y validar parámetros
        amount = float(request.form.get('amount', 0))
        holding_days = int(request.form.get('holding_days', 0))
        
        if amount <= 0 or holding_days <= 0:
            return jsonify({'error': 'Invalid trading parameters'}), 400

        # Obtener el archivo CSV
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        
        # Cargar el CSV en un DataFrame
        input_data = pd.read_csv(file)
        
        # Validar que el DataFrame tenga la columna 'Open'
        if 'Open' not in input_data.columns:
            return jsonify({'error': 'CSV must contain an "Open" column'}), 400

        # Cargar modelo
        model = load_model()
        
        # Calcular predicción usando los últimos datos del CSV
        predictions = calcular_prediccion(
            model,
            input_data.iloc[-1:],  # Usar la última fila del CSV
            amount,
            holding_days
        )
        
        # Enviar resultados al orquestador
        send_results_to_orchestrator(predictions)
        
        return jsonify({'prediction': predictions})

    except ValueError as ve:
        return jsonify({'error': f'Invalid parameter values: {str(ve)}'}), 400
    except Exception as e:
        logger.error(f"Error en predict: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/results', methods=['POST'])
def handle_results():
    try:
        data = request.json
        logger.debug(f"Resultados recibidos: {data}")
        # Aquí puedes procesar los resultados como necesites
        return jsonify({"status": "success", "message": "Resultados recibidos correctamente"}), 200
    except Exception as e:
        logger.error(f"Error processing results: {e}")
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=5011)