from flask import Flask, request, render_template, jsonify
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/search/<string:box>")
def process(box):
    query = request.args.get('query')
    if box == 'names':
        # do some stuff to open your names text file
        # do some other stuff to filter
        # put suggestions in this format...
        suggestions = [{'value': 'joe','data': 'joe'}, {'value': 'jim','data': 'jim'}]
    if box == 'songs':
        # do some stuff to open your songs text file
        # do some other stuff to filter
        # put suggestions in this format...
        suggestions = [{'value': 'song1','data': '123'}, {'value': 'song2','data': '234'}]
    return jsonify({"suggestions":suggestions})

if __name__ == "__main__":
    app.run(debug=True)