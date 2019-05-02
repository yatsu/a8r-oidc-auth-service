const express = require('express')
const logger = require('morgan')

const app = express()

app.use(logger('dev'))

app.get('/healthz', (_, res) => {
  res.sendStatus(200)
})

module.exports = app
