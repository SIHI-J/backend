const express = require('express'); //express 기본 라우팅
//http get, post, put
const app = express(); //app변수에 담기
const port = 9070; //포트번호 설정 21번 ftp 80번 http 443번 https 3306번 mysql
const cors = require('cors'); //cors모듈 가져오기
const bcrypt = require('bcrypt'); //암호화 모듈 가져오기
const saltRounds = 10; // 암호화 강도
const SECRET_KEY = 'your_jwt_secret_key'; // [참고] 실제 서비스에선 환경변수(.env)로 관리하세요.
const jwt = require('jsonwebtoken'); //JWT모듈 가져오기
//프론트에서 보낸 데이터를 서버가 “읽을 수 있게” 해주는 번역기
app.use(cors()); //모든 요청에 대해 cors 허용
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.listen(port, () => {
  console.log(`서버 실행 포트번호 : ${port}`);
}); //서버 실행

//mysql 연결하기
const mysql = require('mysql'); //mysql모듈 가져오기
const connection = mysql.createConnection({
  host: 'database',
  user: 'root',
  password: '1234',
  database: 'kdt'
}); //mysql 접속 정보 입력
connection.connect((err) => {
  if (err) {
    console.error('mysql 연결 실패 : ', err);
    return;
  }
  console.log('mysql 연결 성공!');
}); //mysql 연결 시도

//방법1 메세지만 확인하고자 할때 http://localhost:9070/
app.get('/', (req, res) => {
  //특정 경로로 요청 정보 처리 req 요청 res응답
  res.json('Excuse from Backend!');
}); //루트 경로로 접속 시 'Excuse from Backend!' 메세지 응답
// [회원가입] 비밀번호 암호화하여 저장하기
app.post('/users', async (req, res) => {
  const { userid, username, password } = req.body;

  try {
    // 2. 비밀번호 해싱 (비동기 처리)
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // 3. DB에 저장 (변수명을 connection으로 통일)
    const sql = "INSERT INTO users (userid, username, password) VALUES (?, ?, ?)";
    connection.query(sql, [userid, username, hashedPassword], (err, result) => {
      if (err) {
        console.error('회원가입 쿼리 오류:', err);
        return res.status(500).json({ error: '회원가입 실패 (중복 아이디 등)' });
      }
      res.status(200).json({ message: "회원가입 성공" });
    });
  } catch (error) {
    console.error('암호화 오류:', error);
    res.status(500).send("서버 암호화 오류");
  }
});
// [로그인] 암호화된 비밀번호 검증 및 로그인 처리
app.post('/login', (req, res) => {
  const { userid, password } = req.body;
  const sql = "SELECT * FROM users WHERE userid = ?";
  connection.query(sql, [userid], async (err, results) => {
    if (err) return res.status(500).json({ message: "서버 오류" });
    if (results.length > 0) {
      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        // [수정] JWT 토큰 생성 (사용자 ID를 담아 1시간 동안 유효)
        const token = jwt.sign(
          { userid: user.userid, username: user.username },
          SECRET_KEY,
          { expiresIn: '1h' }
        );

        res.status(200).json({
          message: `${user.username}님 환영합니다!`,
          token: token // 프론트엔드에 토큰 전달
        });
      } else {
        //비밀번호 불일치
        res.status(401).json({ message: "비밀번호가 일치하지 않습니다." });
      }
    } else {
      //아이디 없음
      res.status(404).json({ message: "존재하지 않는 아이디입니다." });
    }
  });
});
//회원가입 아이디 중복 확인
app.get('/ginipet_users', (req, res) => {
  const { username } = req.query;
  const sql = "SELECT * FROM ginipet_users WHERE username = ?";
  data.query(sql, [username], (err, results) => {
    if (err) {
      console.error('중복확인 쿼리 오류:', err);
      return res.status(500).json({ error: 'DB 조회 오류' });
    }
    res.json(results);
  });
});
//회원 가입
app.post('/ginipet_users', async (req, res) => {
  // 프론트에서 보낸 데이터 추출
  const { username, password, tel, email } = req.body;

  try {
    // 비밀번호 암호화
    const hashedPassword = await bcrypt.hash(password, saltRounds); //npm install bcrypt
    const sql = "INSERT INTO ginipet_users (username, password, tel, email) VALUES (?, ?, ?, ?)";

     connection.query(sql, [username, hashedPassword, tel, email], (err, result) => {
      if (err) {
        console.error('MySQL 실행 에러:', err);
        return res.status(500).json({ error: '데이터베이스 저장 실패' });
      }
      res.status(200).json({ message: "회원가입 완료" });
    });
  } catch (error) {
    console.error('bcrypt 암호화 에러:', error);
    res.status(500).json({ error: '서버 내부 에러' });
  }
});
//로그인
app.post('/ginipet_login', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ message: "아이디/비밀번호를 입력해주세요." });
  }

  const sql = "SELECT * FROM ginipet_users WHERE username = ?";
   connection.query(sql, [username], async (err, results) => {
    if (err) return res.status(500).json({ message: "서버 오류" });
    if (results.length === 0) return res.status(404).json({ message: "존재하지 않는 계정입니다." });

    const user = results[0];

    if (!user.password) {
      return res.status(500).json({ message: "비밀번호 데이터가 없습니다." });
    }

    try {
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ message: "비밀번호가 일치하지 않습니다." });

      const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
      return res.status(200).json({ message: `${user.username}님 환영합니다!!`, token });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ message: "인증 처리 중 오류 발생" });
    }
  });
});
//테이블 전체 데이터를 조회 http://localhost:9070/테이블명
app.get('/:table', (req, res) => {
  const table = req.params.table;
  const allowTables = ['fruits', 'goods', 'noodle', 'customer', 'book_store', 'question', 'users'];

  if (!allowTables.includes(table)) {
    return res.status(400).json({ error: '허용되지 않은 테이블' });
  }
  connection.query(`SELECT * FROM ${table}`, (err, results) => {
    if (err) {
      console.error('쿼리 오류:', err);
      return res.status(500).json({ error: 'DB 쿼리 오류' });
    }
    res.json(results);
  });
});

// goods 테이블에 새 상품을 "등록(Create)"하는 라우트
// POST http://localhost:9070/goods
app.post('/goods', (req, res) => {

  // 프론트(React)에서 axios.post로 보낸 데이터
  // 예: { g_name: '초코과자', g_cost: 1500 }
  const { g_name, g_cost } = req.body;

  // 필수값 검증
  // 상품명(g_name)이 없거나, 가격(g_cost)이 undefined면
  // 잘못된 요청이므로 400(Bad Request) 응답
  if (!g_name || g_cost === undefined) {
    return res.status(400).json({
      error: 'g_name, g_cost는 필수입니다.'
    });
  }

  // INSERT 쿼리 작성
  // g_code는 AUTO_INCREMENT이므로 넣지 않음
  // ? 는 SQL Injection 방지를 위한 빈자리
  const sql = 'INSERT INTO goods (g_name, g_cost) VALUES (?, ?)';

  // MySQL에 쿼리 실행
  // Number(g_cost) : 문자열로 들어온 값을 숫자로 변환
  connection.query(sql, [g_name, Number(g_cost)], (err, result) => {

    // DB 에러 발생 시 (컬럼명 오류, NOT NULL 위반 등)
    if (err) {
      console.error('INSERT 오류:', err);
      return res.status(500).json({
        error: 'DB INSERT 오류'
      });
    }

    // 성공 시
    // result.insertId = 새로 생성된 AUTO_INCREMENT 값 (g_code)
    res.status(201).json({
      message: '등록 완료',
      insertId: result.insertId
    });
  });
});
//good 테이블 삭제
app.delete('/goods/:id', (req, res) => {
  const id = req.params.id;
  const sql = 'DELETE FROM goods WHERE g_code = ?';
  connection.query(sql, [id], (err, result) => {
    if (err) {
      console.error('goods 삭제 오류:', err);
      return res.status(500).json({ error: 'db 삭제 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '삭제할 데이터가 없습니다.' });
    }
    res.json({ message: '삭제 완료!' });
  });
});
//goods 수정조회
app.get('/goods/goodsupdate/:g_code', (req, res) => {
  const g_code = req.params.g_code;
  const sql = 'SELECT * FROM goods WHERE g_code = ?';

  connection.query(sql, [g_code], (err, results) => {
    if (err) {
      console.error('GOODS 조회 오류:', err);
      return res.status(500).json({ error: 'DB 조회 오류' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: '데이터가 없습니다.' });
    }
    res.json(results[0]);
  });
});
//goods 수정 입력
app.put('/goods/goodsupdate/:g_code', (req, res) => {
  const g_code = req.params.g_code;
  const { g_name, g_cost } = req.body;

  if (!g_name || g_cost === undefined) {
    return res.status(400).json({ error: 'g_name, g_cost는 필수입니다.' });
  }

  const sql = 'UPDATE goods SET g_name = ?, g_cost = ? WHERE g_code = ?';

  connection.query(sql, [g_name, Number(g_cost), g_code], (err, result) => {
    if (err) {
      console.error('GOODS 수정 오류:', err);
      return res.status(500).json({ error: 'DB 수정 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '수정할 데이터가 없습니다.' });
    }
    res.json({ message: '수정 완료' });
  });
});
// customer 테이블에 신규 데이터 등록
app.post('/customer', (req, res) => {
  // 프론트에서 axios.post로 보낸 데이터
  // { c_name, c_address, c_tel }
  const { c_name, c_address, c_tel } = req.body;

  // 필수값 체크
  if (!c_name || !c_address || !c_tel) {
    return res.status(400).json({
      error: '필수값이 누락되었습니다.'
    });
  }

  // DB에 저장 (전화번호는 이미 00-0000-0000 형태)
  const sql =
    'INSERT INTO customer (c_name, c_address, c_tel) VALUES (?, ?, ?)';

  connection.query(
    sql,
    [c_name, c_address, c_tel],
    (err, result) => {
      if (err) {
        console.error('CUSTOMER INSERT 오류:', err);
        return res.status(500).json({
          error: 'DB INSERT 오류'
        });
      }

      // 성공 응답
      res.status(201).json({
        message: '고객 등록 완료',
        insertId: result.insertId
      });
    }
  );
});
//customer 삭제
app.delete('/customer/:no', (req, res) => {
  const no = req.params.no;
  const sql = 'DELETE FROM customer WHERE no = ?';
  connection.query(sql, [no], (err, result) => {
    if (err) {
      console.error('customer 삭제 오류:', err);
      return res.status(500).json({ error: 'db 삭제 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '삭제할 데이터가 없습니다.' });
    }
    res.json({ message: '삭제 완료!' });
  });
});
//customer 수정조회
app.get('/customer/customerupdate/:no', (req, res) => {
  const no = req.params.no;
  const sql = 'SELECT * FROM customer WHERE no = ?';

  connection.query(sql, [no], (err, results) => {
    if (err) {
      console.error('customer 조회 오류:', err);
      return res.status(500).json({ error: 'DB 조회 오류' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: '데이터가 없습니다.' });
    }
    res.json(results[0]);
  });
});
//customer 수정 입력
app.put('/customer/customerupdate/:no', (req, res) => {
  const no = req.params.no;
  const { c_name, c_address, c_tel } = req.body;

  if (!c_name || !c_address || !c_tel) {
    return res.status(400).json({ error: 'c_name, c_address, c_tel 필수입니다.' });
  }

  const sql = 'UPDATE customer SET c_name = ?, c_address = ?, c_tel = ? WHERE no = ?';

  connection.query(sql, [c_name, c_address, c_tel, no], (err, result) => {
    if (err) {
      console.error('customer 수정 오류:', err);
      return res.status(500).json({ error: 'DB 수정 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '수정할 데이터가 없습니다.' });
    }
    res.json({ message: '수정 완료' });
  });
});
//fruit 입력
app.post('/fruits', (req, res) => {
  const { name, price, color, country } = req.body;

  const sql =
    'INSERT INTO fruits (name, price, color, country) VALUES (?, ?, ?, ?)';

  connection.query(sql, [name, price, color, country], (err) => {
    console.error("FRUITS INSERT ERROR:", err);
    if (err) return res.status(500).json({ error: 'DB INSERT 오류' });
    res.json({ message: '등록 완료' });
  });
});
//fruit 삭제
app.delete('/fruits/:num', (req, res) => {
  const num = req.params.num;
  const sql = 'DELETE FROM fruits WHERE num = ?';
  connection.query(sql, [num], (err, result) => {
    if (err) {
      console.error('fruits 삭제 오류:', err);
      return res.status(500).json({ error: 'db 삭제 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '삭제할 데이터가 없습니다.' });
    }
    res.json({ message: '삭제 완료!' });
  });
});
//fruit 수정 조회
app.get('/fruits/fruitsupdate/:num', (req, res) => {
  const num = req.params.num;
  const sql = 'SELECT * FROM fruits WHERE num = ?';

  connection.query(sql, [num], (err, results) => {
    if (err) {
      console.error('fruits 조회 오류:', err);
      return res.status(500).json({ error: 'DB 조회 오류' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: '데이터가 없습니다.' });
    }
    res.json(results[0]);
  });
});
//fruit 수정 입력
app.put('/fruits/fruitsupdate/:num', (req, res) => {
  const num = req.params.num;
  const { name, price, color, country } = req.body;

  if (!name || !price || !color || !country) {
    return res.status(400).json({ error: 'name, price, color, country 필수입니다.' });
  }

  const sql = 'UPDATE fruits SET name = ?, price = ?, color = ?, country = ? WHERE num = ?';

  connection.query(sql, [name, price, color, country, num], (err, result) => {
    if (err) {
      console.error('fruits 수정 오류:', err);
      return res.status(500).json({ error: 'DB 수정 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '수정할 데이터가 없습니다.' });
    }
    res.json({ message: '수정 완료' });
  });
});
//noodle 입력
app.post('/noodle', (req, res) => {
  const { name, company, kind, price, e_date } = req.body;

  const normalizedEDate = String(e_date || '').replace(/[^0-9]/g, '');

  if (normalizedEDate.length !== 8) {
    return res.status(400).json({
      error: 'e_date는 YYYYMMDD 형식의 8자리 숫자여야 합니다.'
    });
  }

  const sql =
    'INSERT INTO noodle (name, company, kind, price, e_date, reg_date) VALUES (?, ?, ?, ?, ?, NOW())';

  connection.query(
    sql,
    [name, company, kind, price, normalizedEDate],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'DB INSERT 오류' });
      }
      res.json({ message: '등록 완료' });
    }
  );
});

//noodle 삭제
app.delete('/noodle/:num', (req, res) => {
  const num = req.params.num;
  const sql = 'DELETE FROM noodle WHERE num = ?';
  connection.query(sql, [num], (err, result) => {
    if (err) {
      console.error('noodle 삭제 오류:', err);
      return res.status(500).json({ error: 'db 삭제 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '삭제할 데이터가 없습니다.' });
    }
    res.json({ message: '삭제 완료!' });
  });
});
//noodle 수정 조회
app.get('/noodle/noodleupdate/:num', (req, res) => {
  const num = req.params.num;
  const sql = 'SELECT * FROM noodle WHERE num = ?';

  connection.query(sql, [num], (err, result) => {
    if (err) {
      console.error('noodle 조회 오류:', err);
      return res.status(500).json({ error: 'DB조회 오류' });
    }
    if (result.length === 0) {
      return res.status(404).json({ error: '데이터가 없습니다.' });
    }
    res.json(result[0]);
  });
});
//noodle 수정 입력
app.put('/noodle/noodleupdate/:num', (req, res) => {
  const num = req.params.num;
  const { name, company, kind, price, e_date } = req.body;

  const normalizedEDate = String(e_date || '').replace(/[^0-9]/g, '');

  if (normalizedEDate.length !== 8) {
    return res.status(400).json({
      error: 'e_date는 YYYYMMDD 형식의 8자리 숫자여야 합니다.'
    });
  }
  if (!name || !company || !kind || !price || !e_date) {
    return res.status(400).json({ error: '이름, 회사, 종류, 가격, 유통기한, 제조일자를 모두 입력 해 주세요.' });
  }
  const sql =
    'UPDATE noodle SET name = ?, company = ?, kind = ?, price = ?, e_date = ? WHERE num = ?';
  connection.query(
    sql,
    [name, company, kind, price, normalizedEDate, num], (err, result) => {
      if (err) {
        console.error('noodle 수정 오류:', err);
        return res.status(500).json({ error: '데이터 베이스 수정 오류' });
      }
      res.json({ message: '수정 완료' });
    });
});
//bookstore 입력
app.post('/book_store', (req, res) => {
  const { name, area1, area2, area3, book_cnt, owner_nm, tel_num } = req.body;

  const sql =
    'INSERT INTO book_store (name, area1, area2, area3, book_cnt, owner_nm, tel_num) VALUES (?, ?, ?, ?, ?, ?, ?)';

  connection.query(sql, [name, area1, area2, area3, book_cnt, owner_nm, tel_num], (err) => {
    if (err) return res.status(500).json({ error: 'DB INSERT 오류' });
    res.json({ message: '등록 완료' });
  });
});
//bookstore 삭제
app.delete('/book_store/:code', (req, res) => {
  const code = req.params.code;
  const sql = 'DELETE FROM book_store WHERE code = ?';
  connection.query(sql, [code], (err, result) => {
    if (err) {
      console.error('book_store 삭제 오류:', err);
      return res.status(500).json({ error: 'db 삭제 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '삭제할 데이터가 없습니다.' });
    }
    res.json({ message: '삭제 완료!' });
  });
});
//bookstore 수정 조회
app.get('/book_store/book_storeupdate/:code', (req, res) => {
  const code = req.params.code;
  const sql = 'SELECT * FROM book_store WHERE code = ?';

  connection.query(sql, [code], (err, results) => {
    if (err) {
      console.error('book_store 조회 오류:', err);
      return res.status(500).json({ error: 'DB 조회 오류' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: '데이터가 없습니다.' });
    }
    res.json(results[0]);
  });
});
//bookstore 수정 입력
app.put('/book_store/book_storeupdate/:code', (req, res) => {
  const code = req.params.code;
  const { name, area1, area2, area3, book_cnt, owner_nm, tel_num } = req.body;

  if (!name || !area1 || !area2 || !area3 || !book_cnt || !owner_nm || !tel_num) {
    return res.status(400).json({ error: 'name, area1, area2, area3, book_cnt, owner_nm, tel_num 필수입니다.' });
  }

  const sql = 'UPDATE book_store SET name = ?, area1 = ?, area2 = ?, area3 = ?, book_cnt = ?, owner_nm = ?, tel_num = ? WHERE code = ?';

  connection.query(sql, [name, area1, area2, area3, book_cnt, owner_nm, tel_num, code], (err, result) => {
    if (err) {
      console.error('book_store 수정 오류:', err);
      return res.status(500).json({ error: 'DB 수정 오류' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '수정할 데이터가 없습니다.' });
    }
    res.json({ message: '수정 완료' });
  });
});
//contact 입력
app.post('/question', (req, res) => {
  const { id, name, tel, email, txtbox } = req.body;
  const sql =
    'INSERT INTO `question` (`id`, `name`, `tel`, `email`, `txtbox`, `date`) VALUES  (?, ?, ?, ?, ?, NOW())';
  connection.query(
    sql,
    [id, name, tel, email, txtbox],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'DB INSERT 오류' });
      }
      res.json({ message: '등록 완료' });
    }
  );

});




