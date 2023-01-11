instructions = ['USE mailer', 'DROP TABLE IF EXISTS email;', 'DROP TABLE IF EXISTS mailer_users', 'SET FOREIGN_KEY_CHECKS=1;', 'SET FOREIGN_KEY_CHECKS=0;',
    '''
    CREATE TABLE mailer_users(
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(160) NOT NULL,
        username VARCHAR(50) NOT NULL
    )
    ''',
    '''
        CREATE TABLE email(
            id INT PRIMARY KEY AUTO_INCREMENT,
            email TEXT NOT NULL,
            subject TEXT NOT NULL,
            content TEXT NOT NULL,
            created_by INT NOT NULL,
            sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES mailer_users (id)
        );
    '''
]