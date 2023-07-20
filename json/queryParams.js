const queries =
[
    {
        "question":"CREATE TABLE 테이블명(컬럼명 타입명 특징, 컬럼명 타입명...)",
        "answer":"테이블 생성"
    },
    {
        "question":"CREATE (UNIQUE) INDEX 인덱스명 ON 테이블명(컬럼명, 컬럼명...)",
        "answer":"인덱스 생성"
    },
    {
        "question":"CREATE(or REPLACE) VIEW 뷰명 AS SELECT 컬럼명, 컬럼명... FROM 테이블명 WHERE 조건",
        "answer":"뷰 생성"
    },
    {
        "question":"ALTER TABLE 테이블명 ADD (컬럼명 타입명 특징)",
        "answer":"속성 추가"
    },
    {
        "question":"ALTER TABLE 테이블명 MODIFY (컬럼명 타입명 특징)",
        "answer":"속성 수정"
    },
    {
        "question":"ALTER TABLE 테이블명 DROP COLUMN 컬럼명",
        "answer":"속성 삭제"
    },
    {
        "question":"ALTER TABLE 테이블명 RENAME TO 새 테이블명",
        "answer":"테이블명 변경"
    },
    {
        "question":"ALTER TABLE 테이블명 RENAME COLUMN 컬럼명 TO 새 컬럼명",
        "answer":"속성명 변경"
    },
    {
        "question":"DROP TABLE 테이블명 CASCADE/RESTRICT",
        "answer":"테이블 삭제"
    },
    {
        "question":"TRUNCATE TABLE 테이블명",
        "answer":"테이블 내용만 삭제"
    },
    {
        "question":"SELECT 컬럼명,컬럼명 FROM 테이블명 WHERE 조건 ORDER BY 컬럼명 ASC/DESC LIMIT 갯수",
        "answer":"셀렉트문"
    },
    {
        "question":"INSERT INTO 테이블명 VALUES(값1, 값2...);\r\nINSERT INTO 테이블명(컬럼1명, 컬럼2명) VALUES(값1, 값2)",
        "answer":"인서트문 2가지 형태"
    },
    {
        "question":"UPDATE 테이블명 SET 컬럼명1=컬럼값1,컬럼명2=컬럼값2 WHERE 조건",
        "answer":"업데이트문"
    },
    {
        "question":"DELETE FROM 테이블명 WHERE 조건",
        "answer":"딜리트문"
    },
    {
        "question":"SHOW INDEX FROM 테이블명",
        "answer":"인덱스 보기"
    },
    {
        "question":"COMMIT; ROLLBACK; GRANT 권한 ON 테이블명 TO 사용자명;\r\nREVOKE 권한 FROM 테이블명 TO 사용자명",
        "answer":"DCL문 4가지"
    },
    {
        "question":"SELECT * FROM A,B WHERE A.컬럼명=B.컬럼명;\r\n"
        +"SELECT * FROM A JOIN B USING(컬럼명);\r\n"
        +"SELECT * FROM A JOIN B ON A.컬럼명=B.컬럼명;",
        "answer":"조인문 3가지 형태"
    }
];