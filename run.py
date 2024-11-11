import app

if __name__ == "__main__":
    app = app.create_app(None)
    app.run(host='0.0.0.0', port=8080)
