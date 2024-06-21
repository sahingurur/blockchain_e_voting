from flask import Flask, render_template, request, redirect, url_for, flash, session
import hashlib
import datetime
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Gizli anahtar oturumları yönetmek için gereklidir

class Vote:
    def __init__(self, aday_id, aday_adi, il, ilce):
        self.aday_id = aday_id
        self.aday_adi = aday_adi
        self.il = il
        self.ilce = ilce

class Voter:
    def __init__(self, secmen_id, sifre, secmen_il, secmen_ilce):
        self.secmen_id = secmen_id
        self.sifre = sifre
        self.secmen_il = secmen_il
        self.secmen_ilce = secmen_ilce

class MerkleNode:
    def __init__(self, left, right, hash):
        self.left = left
        self.right = right
        self.hash = hash

class MerkleTree:
    def __init__(self, votes):
        self.leaves = [self.hash_vote(vote) for vote in votes]
        self.root = self.build_tree(self.leaves)

    def hash_vote(self, vote):
        vote_data = f"{vote.aday_id}-{vote.il}-{vote.ilce}"
        return hashlib.sha256(vote_data.encode()).hexdigest()

    def build_tree(self, leaves):
        if not leaves:
            return None
        nodes = [MerkleNode(None, None, leaf) for leaf in leaves]
        while len(nodes) > 1:
            temp_nodes = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                if i + 1 < len(nodes):
                    right = nodes[i + 1]
                else:
                    right = left
                combined_hash = hashlib.sha256((left.hash + right.hash).encode()).hexdigest()
                temp_nodes.append(MerkleNode(left, right, combined_hash))
            nodes = temp_nodes
        return nodes[0] if nodes else None

class CoinBlock:
    def __init__(self, oncekiblokhash, merkle_root_hash, zamandamgasi):
        self.oncekiblokhash = oncekiblokhash
        self.merkle_root_hash = merkle_root_hash
        self.zamandamgasi = zamandamgasi
        self.blokveri = f"{merkle_root_hash}-{oncekiblokhash}-{zamandamgasi}"
        self.blokhashdegeri = hashlib.sha256(self.blokveri.encode()).hexdigest()

class Blokzincir:
    def __init__(self):
        self.zincir = []
        self.kullanici_oy_kimlikleri = set()
        self.secmenler = {}
        self.oy_sonuclari = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        self.il_merkle_trees = defaultdict(lambda: defaultdict(MerkleTree))
        self.adaylar = {1: {"isim": "Legolas", "gorsel": "aday_1.png"}, 2: {"isim": "Gimli", "gorsel": "aday_2.png"}}
        self.genesis_blok_olusturucu()

    def genesis_blok_olusturucu(self):
        genesis_merkle_tree = MerkleTree([])
        self.zincir.append(CoinBlock("0", genesis_merkle_tree.root.hash if genesis_merkle_tree.root else "0", datetime.datetime.now()))

    def kullanici_ekle(self, secmen_id, sifre, secmen_il, secmen_ilce):
        self.secmenler[secmen_id] = Voter(secmen_id, sifre, secmen_il, secmen_ilce)

    def kullanici_oy_kontrol(self, secmen_id, sifre):
        if secmen_id in self.kullanici_oy_kimlikleri:
            return "Bu kullanıcı zaten oy kullandı!"
        if secmen_id not in self.secmenler or self.secmenler[secmen_id].sifre != sifre:
            return "Geçersiz kullanıcı ID veya şifre!"
        self.kullanici_oy_kimlikleri.add(secmen_id)
        return "Başarılı"

    def oy_ekle(self, oy, secmen_id, sifre):
        kontrol_mesaji = self.kullanici_oy_kontrol(secmen_id, sifre)
        if kontrol_mesaji != "Başarılı":
            return kontrol_mesaji
        il = self.secmenler[secmen_id].secmen_il
        ilce = self.secmenler[secmen_id].secmen_ilce
        oy.il = il
        oy.ilce = ilce
        self.oy_sonuclari[il][ilce][oy.aday_adi] += 1
        self.blok_guncelle()
        return "Oy başarıyla eklendi!"

    def blok_guncelle(self):
        self.merkle_tree_guncelle()
        oncekiblokhash = self.son_blok.blokhashdegeri if self.son_blok else "0"
        for il, ilceler in self.il_merkle_trees.items():
            for ilce, merkle_tree in ilceler.items():
                merkle_root_hash = merkle_tree.root.hash if merkle_tree.root else "0"
                yeni_blok = CoinBlock(oncekiblokhash, merkle_root_hash, datetime.datetime.now())
                self.zincir.append(yeni_blok)
                oncekiblokhash = yeni_blok.blokhashdegeri

    def merkle_tree_guncelle(self):
        for il, ilceler in self.oy_sonuclari.items():
            for ilce, oylar in ilceler.items():
                if oylar:
                    votes = [Vote(None, aday, il, ilce) for aday, count in oylar.items() for _ in range(count)]
                    self.il_merkle_trees[il][ilce] = MerkleTree(votes)

    def oy_sonuclari_goster(self):
        results = []
        for il, ilceler in self.oy_sonuclari.items():
            for ilce, oylar in ilceler.items():
                for aday, count in oylar.items():
                    results.append((il, ilce, aday, count))
        return results

    def merkle_root_goster(self):
        self.merkle_tree_guncelle()
        roots = []
        for il, ilceler in self.il_merkle_trees.items():
            for ilce, merkle_tree in ilceler.items():
                roots.append((il, ilce, merkle_tree.root.hash if merkle_tree.root else 'Yok'))
        return roots

    def blok_dogrulama(self):
        valid_blocks = []
        for i, blok in enumerate(self.zincir[1:], start=1):
            valid_blocks.append((i + 1, blok.oncekiblokhash == self.zincir[i-1].blokhashdegeri))
        return valid_blocks

    @property
    def son_blok(self):
        return self.zincir[-1] if self.zincir else None

blok_zincirim = Blokzincir()

blok_zincirim.kullanici_ekle("user1", "pass1", "İstanbul", "Kadıköy")
blok_zincirim.kullanici_ekle("user2", "pass2", "Ankara", "Çankaya")
blok_zincirim.kullanici_ekle("user3", "pass3", "İzmir", "Konak")
blok_zincirim.kullanici_ekle("user4", "pass4", "Bursa", "Osmangazi")

blok_zincirim.adaylar = {
    1: {"isim": "Aday1", "gorsel": "aday_1.png"},
    2: {"isim": "Aday2", "gorsel": "aday_2.png"}
}

admins = {
    "admin": "admin123"
}

@app.before_request
def clear_flash():
    session.modified = True  # Oturumu değiştirildi olarak işaretle
    if '_flashes' in session:
        session.pop('_flashes', None)

@app.route('/')
def index():
    adaylar = blok_zincirim.adaylar  # Aday bilgilerini al
    return render_template('index.html', adaylar=adaylar)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_id = request.form['admin_id']
        sifre = request.form['sifre']
        if admin_id in admins and admins[admin_id] == sifre:
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        else:
            flash("Geçersiz admin ID veya şifre!", "danger")
    return render_template('admin_login.html')

@app.route('/admin_panel')
def admin_panel():
    if 'admin' in session:
        return render_template('admin_panel.html')
    else:
        flash("Yetkisiz erişim!", "danger")
        return redirect(url_for('admin_login'))

@app.route('/results')
def results():
    if 'admin' in session:
        oy_sonuclari = blok_zincirim.oy_sonuclari_goster()
        return render_template('results.html', oy_sonuclari=oy_sonuclari)
    else:
        flash("Yetkisiz erişim!", "danger")
        return redirect(url_for('admin_login'))

@app.route('/merkle_roots')
def merkle_roots():
    if 'admin' in session:
        roots = blok_zincirim.merkle_root_goster()
        return render_template('merkle_roots.html', roots=roots)
    else:
        flash("Yetkisiz erişim!", "danger")
        return redirect(url_for('admin_login'))

@app.route('/verify_blocks')
def verify_blocks():
    if 'admin' in session:
        valid_blocks = blok_zincirim.blok_dogrulama()
        return render_template('verify_blocks.html', valid_blocks=valid_blocks)
    else:
        flash("Yetkisiz erişim!", "danger")
        return redirect(url_for('admin_login'))

@app.route('/admin_results')
def admin_results():
    if 'admin' in session:
        oy_sonuclari = blok_zincirim.oy_sonuclari_goster()
        return render_template('admin_results.html', oy_sonuclari=oy_sonuclari)
    else:
        flash("Yetkisiz erişim!", "danger")
        return redirect(url_for('admin_login'))

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        secmen_id = request.form['secmen_id']
        sifre = request.form['sifre']
        if secmen_id in blok_zincirim.secmenler and blok_zincirim.secmenler[secmen_id].sifre == sifre:
            session['user'] = secmen_id
            return redirect(url_for('vote'))
        else:
            flash("Geçersiz kullanıcı ID veya şifre!", "danger")
    return render_template('user_login.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'user' not in session:
        flash("Oy kullanmak için lütfen giriş yapın.", "danger")
        return redirect(url_for('user_login'))

    adaylar = blok_zincirim.adaylar  # Aday bilgilerini al

    if request.method == 'POST':
        aday_id = int(request.form['aday_id'])
        aday = adaylar.get(aday_id)  # Adayı al, None dönebilir
        if aday is None:
            flash("Geçersiz aday ID'si!", "danger")
            return redirect(url_for('vote'))

        secmen_id = session.get('user')  # Kullanıcı ID'sini al
        if secmen_id in blok_zincirim.kullanici_oy_kimlikleri:
            flash("Kullanıcı yeniden oy kullanamaz.", "danger")
            return redirect(url_for('index'))  # Oy kullanmaya devam etmeden önce ana sayfaya yönlendir

        sifre = blok_zincirim.secmenler[secmen_id].sifre  # Şifreyi doğrudan kullanıcıdan al
        message = blok_zincirim.oy_ekle(Vote(aday_id, aday['isim'], "", ""), secmen_id, sifre)  # Şifreyi kullanarak oy ekle
        if message == "Oy başarıyla eklendi!":
            flash("Oy verme başarılı.", "success")
        else:
            flash(message, "danger")
        
        return redirect(url_for('vote'))  # Kullanıcıyı oy verme sayfasında tutarak uyarı mesajını göster

    return render_template('vote.html', adaylar=adaylar)

if __name__ == '__main__':
    app.run(debug=True)
