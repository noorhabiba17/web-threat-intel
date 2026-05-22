Render deployment notes

1) Set up a new Web Service on Render connected to this repository.
2) In Render's dashboard, set the build command to: `pip install -r requirements.txt`
3) Set the start command to: `gunicorn "app:create_app()" --bind 0.0.0.0:$PORT`
4) Add environment variables (in the Render dashboard):
   - `FLASK_ENV=production`
   - `SECRET_KEY` (a strong random value)
   - `OPENROUTER_API_KEY` (your OpenRouter key)
5) Do NOT commit secrets to the repo—the `.env` file is ignored by `.gitignore`.
6) Remove any local tunneling services (ngrok) from your deployment workflow; Render provides routing.

If you'd like, I can also add `gunicorn` to `requirements.txt` and prepare a one-click `render.yaml`.