from fastapi import FastAPI,HTTPException
from .core import from_dict,verify,to_dict
from .mutation import benchmark
from .diagnosis import diagnose,repair
app=FastAPI(title="NetTwin API",version="0.1.0")
@app.get('/health')
def health(): return {"status":"ok"}
@app.post('/verify')
def check(payload:dict):
    try:return verify(from_dict(payload))
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc))
@app.post('/mutate')
def mutate(payload:dict):
    try:return benchmark(from_dict(payload))
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc))
@app.post('/diagnose')
def diagnose_route(payload:dict):
    try:return diagnose(from_dict(payload))
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc))
@app.post('/repair')
def repair_route(payload:dict):
    try:
        result=repair(from_dict(payload))
        return {"success":result['success'],"change":result['change'],"configuration":to_dict(result['scenario'])}
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc))
