from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import auth, workouts, routines
from api.database import Base, engine

app = FastAPI()
Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_headers=['*'],
    allow_methods=['*']
)


@ app.get('/')
def health_check():
    return 'Health check complete'


app.include_router(auth.router)
app.include_router(workouts.router)
app.include_router(routines.router)