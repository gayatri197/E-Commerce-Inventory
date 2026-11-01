from flask import Flask, request, jsonify
from agent import agent
from db import init_db

app = Flask(__name__)

init_db()

@app.route("/agent", methods=["POST"])
def run_agent():
    data = request.json
    user_input = data["input"]

    result = agent(user_input)

    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(debug=True)
