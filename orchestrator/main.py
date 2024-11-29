from flask import Flask, request, jsonify
import requests
import pandas as pd
import logging
import traceback

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/', methods=['GET'])
def health_check():
    """Ruta de verificación de estado"""
    return jsonify({'status': 'Orchestrator API is running'})

def send_results_to_ui(predictions):
    try:
        ui_results_url = 'http://app:5010/interface'
        payload = {'predictions': predictions}
        response = requests.post(ui_results_url, json=payload)
        if response.status_code == 200:
            logger.info("Resultados enviados a la interfaz de usuario correctamente.")
        else:
            logger.error(f"Error al enviar los resultados a la interfaz de usuario: {response.status_code}")
    except Exception as e:
        logger.error(f"Error al enviar los resultados a la interfaz de usuario: {e}")

@app.route('/upload', methods=['POST'])
def handle_upload():
    try:
        logger.debug("=== Iniciando nueva solicitud de upload ===")
        logger.debug(f"Headers recibidos: {dict(request.headers)}")
        logger.debug(f"Form data: {dict(request.form)}")
        logger.debug(f"Files: {request.files}")

        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        model = request.form.get('model', 'amazon')
        amount = request.form.get('amount')
        holding_days = request.form.get('holding_days')

        logger.debug(f"Archivo recibido: {file.filename}")
        logger.debug(f"Modelo seleccionado: {model}")
        logger.debug(f"Cantidad a invertir: {amount}")
        logger.debug(f"Días de holding: {holding_days}")

        df = pd.read_csv(file)
        logger.debug(f"DataFrame cargado con las siguientes columnas: {df.columns}")

        model_url = f'http://ml_models:5011/{model}/predict'
        file_content_transformed = df.to_csv(index=False)

        # Preparar la solicitud para el modelo ML
        files = {'file': (file.filename, file_content_transformed, 'text/csv')}
        data = {
            'amount': amount,
            'holding_days': holding_days
        }

        response = requests.post(
            model_url,
            files=files,
            data=data
        )

        if response.status_code == 200:
            logger.debug(f"Archivo enviado exitosamente al modelo: {model_url}")
            predictions = response.json()['prediction']
            return jsonify({
                'message': 'Archivo enviado exitosamente al modelo',
                'predictions': predictions
            }), 200
        else:
            logger.error(f"Error al enviar el archivo al modelo: {response.text}")
            return jsonify({'error': f"Error del modelo: {response.text}"}), response.status_code

    except Exception as e:
        logger.error("Error no manejado en handle_upload")
        logger.error(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=5012)