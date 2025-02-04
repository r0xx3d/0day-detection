from flask import Flask, render_template

app = Flask(__name__)


@app.route('/')
def index():
	return render_template('index.html')

@app.route('/dynamic-analysis')
def dynamic_analysis():
	return render_template('dynamic-analysis.html')

if __name__ == "__main__":
	app.run(debug=True)


