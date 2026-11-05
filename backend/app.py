"""YKNOVA Studio API. Deploy with a persistent volume and HTTPS reverse proxy.
Payments are disabled unless Razorpay live credentials are configured.
"""
import os, sqlite3, json, secrets, hashlib, hmac, base64, time, uuid, shutil, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import jwt
from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

BASE=Path(__file__).parent
DATA=Path(os.getenv('DATA_DIR',str(BASE/'data')))
DATA.mkdir(parents=True,exist_ok=True)
IMAGES=DATA/'images'; PACKAGES=DATA/'packages'; IMAGES.mkdir(exist_ok=True); PACKAGES.mkdir(exist_ok=True)
DB=DATA/'studio.sqlite3'
SECRET=os.environ.get('JWT_SECRET','')
if not SECRET:
 if os.getenv('RENDER') or os.getenv('PRODUCTION') == '1':
  raise RuntimeError('JWT_SECRET must be configured for deployed environments')
 SECRET=secrets.token_hex(32); print('WARNING: temporary JWT_SECRET; configure a persistent value before deployment')
ORIGINS=[x.strip() for x in os.getenv('FRONTEND_ORIGINS','http://localhost:8000,http://127.0.0.1:8000').split(',') if x.strip()]
KEY_ID=os.getenv('RAZORPAY_KEY_ID','')
KEY_SECRET=os.getenv('RAZORPAY_KEY_SECRET','')
WEBHOOK_SECRET=os.getenv('RAZORPAY_WEBHOOK_SECRET','')
PAYMENTS_ENABLED=bool(KEY_ID and KEY_SECRET and KEY_ID.startswith('rzp_live_'))
app=FastAPI(title='YKNOVA Studio API',version='2.0')
app.add_middleware(CORSMiddleware,allow_origins=ORIGINS,allow_credentials=False,allow_methods=['GET','POST','PUT','DELETE','OPTIONS'],allow_headers=['Authorization','Content-Type'])
app.mount('/images',StaticFiles(directory=str(IMAGES)),name='images')

def conn():
 c=sqlite3.connect(DB,timeout=30);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c

def init():
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,pw TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer',created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY,title TEXT NOT NULL,slug TEXT UNIQUE NOT NULL,category TEXT NOT NULL,description TEXT NOT NULL,price INTEGER NOT NULL,license TEXT NOT NULL,preview TEXT NOT NULL DEFAULT '',package TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'draft',tags TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,total INTEGER NOT NULL,status TEXT NOT NULL,razorpay_order_id TEXT UNIQUE,razorpay_payment_id TEXT UNIQUE,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
  CREATE TABLE IF NOT EXISTS order_items(order_id TEXT NOT NULL,product_id TEXT NOT NULL,unit_price INTEGER NOT NULL,PRIMARY KEY(order_id,product_id));
  CREATE TABLE IF NOT EXISTS wishlist(user_id TEXT NOT NULL,product_id TEXT NOT NULL,PRIMARY KEY(user_id,product_id));''')
  c.execute('CREATE INDEX IF NOT EXISTS orders_user ON orders(user_id)')
  email=os.getenv('ADMIN_EMAIL','').lower().strip();pw=os.getenv('ADMIN_PASSWORD','')
  if email and pw:
   if len(pw)<12: raise RuntimeError('ADMIN_PASSWORD must be >=12 characters')
   if not c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone():
    c.execute('INSERT INTO users VALUES(?,?,?,?,?,?)',(uuid.uuid4().hex,email,'Store Administrator',hash_password(pw),'admin',now()))
    print('Initial admin created:',email)

def now():return datetime.now(timezone.utc).isoformat()
def hash_password(pw):
 salt=secrets.token_bytes(16);dk=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,250000)
 return base64.b64encode(salt+dk).decode()
def verify_password(pw,encoded):
 try:
  blob=base64.b64decode(encoded);return hmac.compare_digest(blob[16:],hashlib.pbkdf2_hmac('sha256',pw.encode(),blob[:16],250000))
 except Exception:return False

def token(user):return jwt.encode({'sub':user['id'],'role':user['role'],'exp':int(time.time())+60*60*24},SECRET,algorithm='HS256')

def auth(authorization:Optional[str]=Header(default=None)):
 if not authorization or not authorization.startswith('Bearer '):raise HTTPException(401,'Sign in required')
 try:uid=jwt.decode(authorization[7:],SECRET,algorithms=['HS256'])['sub']
 except Exception:raise HTTPException(401,'Invalid or expired session')
 with conn() as c:u=c.execute('SELECT id,email,name,role,created_at FROM users WHERE id=?',(uid,)).fetchone()
 if not u:raise HTTPException(401,'Account not found')
 return dict(u)
def admin(user=Depends(auth)):
 if user['role']!='admin':raise HTTPException(403,'Admin access required')
 return user

class Register(BaseModel):
 name:str=Field(min_length=2,max_length=120)
 email:EmailStr
 password:str=Field(min_length=10,max_length=128)
class Login(BaseModel):
 email:EmailStr; password:str
class Checkout(BaseModel):
 product_ids:list[str]=Field(min_length=1,max_length=30)
class Wish(BaseModel):product_id:str

@app.on_event('startup')
def startup():init()

@app.get('/api/health')
def health():return {'status':'ok','payments_enabled':PAYMENTS_ENABLED}

@app.post('/api/register')
def register(body:Register):
 uid=uuid.uuid4().hex
 try:
  with conn() as c:c.execute('INSERT INTO users VALUES(?,?,?,?,?,?)',(uid,body.email.lower(),body.name,hash_password(body.password),'customer',now()))
 except sqlite3.IntegrityError:raise HTTPException(409,'Email already registered')
 with conn() as c:u=dict(c.execute('SELECT id,name,email,role,created_at FROM users WHERE id=?',(uid,)).fetchone())
 return {'token':token(u),'user':u}

@app.post('/api/login')
def login(body:Login):
 with conn() as c:u=c.execute('SELECT * FROM users WHERE email=?',(body.email.lower(),)).fetchone()
 if not u or not verify_password(body.password,u['pw']):raise HTTPException(401,'Invalid credentials')
 usr={k:u[k] for k in ('id','email','name','role','created_at')}
 return {'token':token(usr),'user':usr}

@app.get('/api/me')
def me(user=Depends(auth)):return user

def product_dict(row):
 d=dict(row);d.pop('package',None);d['tags']=[x for x in d['tags'].split(',') if x];return d

@app.get('/api/products')
def products(category:str='',search:str=''):
 q="SELECT * FROM products WHERE status='published'";args=[]
 if category and category!='All':q+=' AND category=?';args.append(category)
 if search:q+=' AND (title LIKE ? OR description LIKE ?)';args+=['%'+search+'%']*2
 q+=' ORDER BY created_at DESC LIMIT 200'
 with conn() as c:return [product_dict(r) for r in c.execute(q,args).fetchall()]

@app.get('/api/products/{pid}')
def get_product(pid:str):
 with conn() as c:p=c.execute("SELECT * FROM products WHERE (id=? OR slug=?) AND status='published'",(pid,pid)).fetchone()
 if not p:raise HTTPException(404,'Product not found')
 return product_dict(p)

@app.get('/api/admin/products')
def admin_products(user=Depends(admin)):
 with conn() as c:return [product_dict(x) for x in c.execute('SELECT * FROM products ORDER BY created_at DESC').fetchall()]

@app.post('/api/admin/products')
def create_product(title:str=Form(...),category:str=Form(...),price:int=Form(...),description:str=Form(''),license:str=Form('Personal and commercial license'),tags:str=Form(''),status:str=Form('draft'),preview:Optional[UploadFile]=File(None),package:Optional[UploadFile]=File(None),user=Depends(admin)):
 if len(title)>150 or len(description)>12000 or price<0 or price>100000000 or status not in ('draft','published'):raise HTTPException(422,'Invalid product fields')
 if category not in ['Landing Pages','Dashboards','Portfolios','Business','SaaS','Components','Bundles','Other']:raise HTTPException(422,'Invalid category')
 if status=='published' and not package:raise HTTPException(422,'Product ZIP required to publish')
 pid=uuid.uuid4().hex;slug=''.join(ch if ch.isalnum() else '-' for ch in title.lower()).strip('-')[:80]+'-'+pid[:6]
 image_name=save_upload(preview,IMAGES,('image/png','image/jpeg','image/webp'),8*1024*1024) if preview else ''
 package_name=save_upload(package,PACKAGES,('application/zip','application/x-zip-compressed','application/octet-stream'),100*1024*1024,zip_check=True) if package else ''
 with conn() as c:c.execute('INSERT INTO products VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(pid,title,slug,category,description,price,license,image_name,package_name,status,tags,now()))
 return {'id':pid,'status':status}

def save_upload(upload,directory,mime_types,max_size,zip_check=False):
 if upload.content_type not in mime_types:raise HTTPException(422,'Unsupported file type')
 extension=Path(upload.filename or '').suffix.lower()
 if extension not in (['.zip'] if zip_check else ['.jpg','.jpeg','.png','.webp']):raise HTTPException(422,'Invalid file extension')
 name=uuid.uuid4().hex+extension;path=directory/name;total=0
 try:
  with path.open('wb') as f:
   while chunk:=upload.file.read(1024*1024):
    total+=len(chunk)
    if total>max_size:raise HTTPException(413,'Upload too large')
    f.write(chunk)
  if zip_check:
   import zipfile
   if not zipfile.is_zipfile(path):raise HTTPException(422,'Invalid ZIP file')
   with zipfile.ZipFile(path) as archive:
    members=archive.infolist()
    if len(members)>5000 or sum(m.file_size for m in members)>500*1024*1024:
     raise HTTPException(422,'ZIP archive has too many or overly large uncompressed files')
  else:
   from PIL import Image
   with Image.open(path) as im:im.verify()
 except Exception:
  path.unlink(missing_ok=True);raise
 return name

@app.put('/api/admin/products/{pid}')
def edit_product(pid:str,title:str=Form(...),category:str=Form(...),price:int=Form(...),description:str=Form(''),license:str=Form('Personal and commercial license'),tags:str=Form(''),status:str=Form('draft'),preview:Optional[UploadFile]=File(None),package:Optional[UploadFile]=File(None),user=Depends(admin)):
 with conn() as c:old=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
 if not old:raise HTTPException(404,'Product not found')
 if status not in ('draft','published') or price<0 or price>100000000 or len(title)>150 or len(description)>12000:raise HTTPException(422,'Invalid product fields')
 if category not in ['Landing Pages','Dashboards','Portfolios','Business','SaaS','Components','Bundles','Other']:raise HTTPException(422,'Invalid category')
 img=save_upload(preview,IMAGES,('image/png','image/jpeg','image/webp'),8*1024*1024) if preview else old['preview']
 pkg=save_upload(package,PACKAGES,('application/zip','application/x-zip-compressed','application/octet-stream'),100*1024*1024,zip_check=True) if package else old['package']
 if status=='published' and not pkg:raise HTTPException(422,'Product ZIP required to publish')
 with conn() as c:c.execute('UPDATE products SET title=?,category=?,price=?,description=?,license=?,tags=?,status=?,preview=?,package=? WHERE id=?',(title,category,price,description,license,tags,status,img,pkg,pid))
 return {'id':pid,'status':status}

@app.delete('/api/admin/products/{pid}')
def unpublish(pid:str,user=Depends(admin)):
 with conn() as c:c.execute("UPDATE products SET status='draft' WHERE id=?",(pid,))
 return {'status':'draft'}

@app.get('/api/admin/overview')
def overview(user=Depends(admin)):
 with conn() as c:
  count=lambda q:c.execute(q).fetchone()[0]
  orders=[dict(r) for r in c.execute('SELECT o.id,o.total,o.status,o.created_at,u.name AS customer FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.created_at DESC LIMIT 12')]
  return {'revenue':count("SELECT COALESCE(SUM(total),0) FROM orders WHERE status='paid'"),'orders':count("SELECT COUNT(*) FROM orders WHERE status='paid'"),'templates':count("SELECT COUNT(*) FROM products WHERE status='published'"),'customers':count("SELECT COUNT(*) FROM users WHERE role='customer'"),'recent_orders':orders}

@app.get('/api/admin/orders')
def all_orders(user=Depends(admin)):
 with conn() as c:return [dict(r) for r in c.execute('SELECT o.*,u.email AS customer_email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.created_at DESC LIMIT 300')]

@app.get('/api/admin/customers')
def all_customers(user=Depends(admin)):
 with conn() as c:return [dict(r) for r in c.execute("SELECT id,name,email,created_at FROM users WHERE role='customer' ORDER BY created_at DESC LIMIT 300")]

@app.get('/api/orders')
def my_orders(user=Depends(auth)):
 with conn() as c:
  rows=c.execute('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC',(user['id'],)).fetchall()
  return [{**dict(x),'items':[dict(y) for y in c.execute('SELECT p.id,p.title,p.preview,oi.unit_price FROM order_items oi JOIN products p ON oi.product_id=p.id WHERE oi.order_id=?',(x['id'],))]} for x in rows]

@app.get('/api/library')
def library(user=Depends(auth)):
 with conn() as c:
  return [product_dict(r) for r in c.execute("SELECT DISTINCT p.* FROM products p JOIN order_items oi ON p.id=oi.product_id JOIN orders o ON o.id=oi.order_id WHERE o.user_id=? AND o.status='paid' ORDER BY o.created_at DESC",(user['id'],))]

@app.get('/api/library/{pid}/download')
def download(pid:str,user=Depends(auth)):
 with conn() as c:
  row=c.execute("SELECT p.package,p.title FROM products p JOIN order_items oi ON p.id=oi.product_id JOIN orders o ON o.id=oi.order_id WHERE p.id=? AND o.user_id=? AND o.status='paid' LIMIT 1",(pid,user['id'])).fetchone()
 if not row or not row['package']:raise HTTPException(403,'No paid download entitlement')
 path=PACKAGES/row['package']
 if not path.is_file():raise HTTPException(404,'File unavailable; contact support')
 return FileResponse(path,media_type='application/zip',filename=(row['title'][:70].replace('/','-')+'.zip'))

@app.get('/api/wishlist')
def get_wishlist(user=Depends(auth)):
 with conn() as c:return [r[0] for r in c.execute('SELECT product_id FROM wishlist WHERE user_id=?',(user['id'],))]

@app.post('/api/wishlist')
def add_wishlist(body:Wish,user=Depends(auth)):
 with conn() as c:c.execute('INSERT OR IGNORE INTO wishlist VALUES(?,?)',(user['id'],body.product_id))
 return {'ok':True}

@app.delete('/api/wishlist/{pid}')
def delete_wishlist(pid:str,user=Depends(auth)):
 with conn() as c:c.execute('DELETE FROM wishlist WHERE user_id=? AND product_id=?',(user['id'],pid))
 return {'ok':True}

def razor_request(endpoint,payload):
 auth=base64.b64encode(f'{KEY_ID}:{KEY_SECRET}'.encode()).decode()
 req=urllib.request.Request('https://api.razorpay.com/v1/'+endpoint,data=json.dumps(payload).encode(),headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=15) as response:return json.load(response)
 except urllib.error.HTTPError as ex:raise HTTPException(502,'Gateway rejected checkout') from ex
 except Exception as ex:raise HTTPException(502,'Payment gateway unavailable') from ex

@app.post('/api/checkout')
def checkout(body:Checkout,user=Depends(auth)):
 if not PAYMENTS_ENABLED:raise HTTPException(503,'Payments are not yet activated. Please check back after launch.')
 ids=list(dict.fromkeys(body.product_ids))
 with conn() as c:
  rows=c.execute('SELECT id,title,price FROM products WHERE status=\'published\' AND id IN ('+','.join('?'*len(ids))+')',ids).fetchall()
 if len(rows)!=len(ids):raise HTTPException(400,'Some products are unavailable')
 total=sum(r['price'] for r in rows)
 if total<100:raise HTTPException(400,'Minimum gateway amount is ₹1')
 order_id=uuid.uuid4().hex
 rz=razor_request('orders',{'amount':total,'currency':'INR','receipt':order_id[:40],'notes':{'studio_order':order_id}})
 with conn() as c:
  c.execute('INSERT INTO orders(id,user_id,total,status,razorpay_order_id,created_at) VALUES(?,?,?,?,?,?)',(order_id,user['id'],total,'pending',rz['id'],now()))
  c.executemany('INSERT INTO order_items VALUES(?,?,?)',[(order_id,r['id'],r['price']) for r in rows])
 return {'order_id':order_id,'razorpay_order_id':rz['id'],'amount':total,'currency':'INR','key_id':KEY_ID,'name':'YKNOVA Studio'}

class VerifyPay(BaseModel):
 razorpay_order_id:str;razorpay_payment_id:str;razorpay_signature:str
@app.post('/api/checkout/verify')
def verify_checkout(body:VerifyPay,user=Depends(auth)):
 expected=hmac.new(KEY_SECRET.encode(),(body.razorpay_order_id+'|'+body.razorpay_payment_id).encode(),hashlib.sha256).hexdigest() if KEY_SECRET else ''
 if not hmac.compare_digest(expected,body.razorpay_signature):raise HTTPException(400,'Payment signature invalid')
 with conn() as c:
  order=c.execute('SELECT * FROM orders WHERE razorpay_order_id=? AND user_id=?',(body.razorpay_order_id,user['id'])).fetchone()
  if not order:raise HTTPException(404,'Order not found')
  if order['status']=='paid':
   if order['razorpay_payment_id'] != body.razorpay_payment_id:raise HTTPException(409,'Order already paid by a different payment')
   return {'status':'paid'}
  c.execute("UPDATE orders SET status='paid',razorpay_payment_id=? WHERE id=? AND status='pending'",(body.razorpay_payment_id,order['id']))
 return {'status':'paid'}

@app.post('/api/checkout/webhook')
async def webhook(request:Request):
 if not WEBHOOK_SECRET:raise HTTPException(503,'Webhook not configured')
 body=await request.body();sig=request.headers.get('X-Razorpay-Signature','')
 expected=hmac.new(WEBHOOK_SECRET.encode(),body,hashlib.sha256).hexdigest()
 if not hmac.compare_digest(expected,sig):raise HTTPException(401,'Invalid webhook signature')
 payload=json.loads(body)
 if payload.get('event')=='payment.captured':
  entity=payload.get('payload',{}).get('payment',{}).get('entity',{})
  with conn() as c:c.execute("UPDATE orders SET status='paid',razorpay_payment_id=? WHERE razorpay_order_id=? AND status='pending'",(entity.get('id'),entity.get('order_id')))
 return {'ok':True}

@app.get('/')
def root():return {'service':'YKNOVA Studio API','health':'/api/health'}

class ProfileUpdate(BaseModel):
 name:str=Field(min_length=2,max_length=120)
@app.put('/api/me')
def update_profile(body:ProfileUpdate,user=Depends(auth)):
 with conn() as c:c.execute('UPDATE users SET name=? WHERE id=?',(body.name.strip(),user['id']))
 return {**user,'name':body.name.strip()}

class PasswordUpdate(BaseModel):
 current_password:str
 new_password:str=Field(min_length=10,max_length=128)
@app.put('/api/me/password')
def change_password(body:PasswordUpdate,user=Depends(auth)):
 with conn() as c:
  row=c.execute('SELECT pw FROM users WHERE id=?',(user['id'],)).fetchone()
  if not row or not verify_password(body.current_password,row['pw']):raise HTTPException(400,'Current password is incorrect')
  c.execute('UPDATE users SET pw=? WHERE id=?',(hash_password(body.new_password),user['id']))
 return {'ok':True}
