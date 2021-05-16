# Install dependencies

You need to install [composer](https://getcomposer.org/download/) first, then run:

```bash
composer install
```

# Create .env file

```bash
touch .env
```

```
DB_HOST=<your db host>
DB_NAME=<your db name>
DB_USER=<your db user>
DB_PASS=<your db pass>
JWT_KEY=<random string>
```

# Start server

First time:

```bash
chmod +x start.sh
```

Then run:

```bash
./start.sh
```
