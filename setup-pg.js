const bcrypt = require('bcrypt');
const db = require('./db');

async function createAdmin() {
    try {
        const username = 'admin';
        const password = await bcrypt.hash('admin123', 10);
        
        // Check if admin already exists
        const existingAdmin = await db.get(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );

        if (existingAdmin) {
            console.log('Admin user already exists');
            return;
        }

        // Create admin user
        await db.run(
            'INSERT INTO users (username, password, role, display_name) VALUES ($1, $2, $3, $4)',
            [username, password, 'admin', 'Administrator']
        );

        console.log('Admin user created successfully');
    } catch (err) {
        console.error('Error creating admin:', err);
    }
}

// Run the setup
createAdmin(); 