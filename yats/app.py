from flask import Flask, request
from flask_restful import Resource, Api

app = Flask(__name__)
api = Api(app)

tasks = {}


class Task(Resource):
    def get(self, task_id):
        return {task_id: tasks[task_id]}

    def post(self):
        payload = request.get_json()
        print(payload)
        task_id = len(tasks)
        tasks[task_id] = payload
        return {task_id: tasks[task_id]}, 201

    def put(self, task_id):
        tasks[task_id] = request.get_json()
        return {task_id: tasks[task_id]}

    def delete(self, task_id):
        del tasks[task_id]


api.add_resource(Task, '/', '/<int:task_id>')

if __name__ == '__main__':
    app.run(debug=True)
