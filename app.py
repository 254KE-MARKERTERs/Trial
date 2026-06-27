from flask import Flask, request, jsonify, render_template
import requests, time, random, os
app = Flask(__name__)
HF_TOKEN = os.environ.get("HF_TOKEN")
if not HF_TOKEN:
    raise RuntimeError("HF_TOKEN environment variable not set")
HF_API_URL = "https://api-inference.huggingface.co/models/microsoft/DialoGPT-medium"
HEADERS = {"Authorization": f"Bearer {HF_TOKEN}"}
def chat_with_hf(prompt):
    payload = {"inputs": prompt}
    try:
        r = requests.post(HF_API_URL, headers=HEADERS, json=payload, timeout=30)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and len(data) > 0:
                return data[0].get("generated_text", "I'm not sure.")
            return "I didn't understand that."
        return f"API error: {r.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message', '')
    if not user_message:
        return jsonify({"response": "Please say something."})
    time.sleep(random.uniform(1.0, 3.0))
    reply = chat_with_hf(user_message)
    if len(reply) < 5:
        reply = "Interesting. " + reply
    return jsonify({"response": reply})
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
