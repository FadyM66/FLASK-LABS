from flask import Flask, render_template, url_for, redirect
app = Flask(__name__)

students = [
    {
        "name": "John Doe",
        "id": 1,
        "major": "Computer Science"
    },
    {
        "name": "Jane Smith",
        "id": 2,
        "major": "Mathematics"
    },
    {
        "name": "Emily Johnson",
        "id": 3,
        "major": "Physics"
    }
]

@app.route('/students')
def students_page():
    return render_template('index.html', students=students) 

@app.route('/search/<int:id>')
def search(id):
    return render_template('search.html', students=students, id=id)

if __name__=='__main__':
    print(app.url_map)
    app.run(debug=True ,port=5000)