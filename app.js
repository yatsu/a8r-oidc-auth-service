const cookieParse = require('cookie-parser')
const createDebug = require('debug')
const express = require('express')
const session = require('express-session')
const logger = require('morgan')
const passport = require('passport')
const { Issuer, Strategy } = require('openid-client')

const log = {
  info: createDebug('a8r-oidc-auth-service:info'),
  debug: createDebug('a8r-oidc-auth-service:debug')
}

async function appSetup() {
  log.info('OIDC provider: %s', process.env.OIDC_PROVIDER)
  const issuer = await Issuer.discover(process.env.OIDC_PROVIDER)

  log.info(
    'OIDC client: %s redirect_uri: %s',
    process.env.OIDC_CLIENT_ID,
    process.env.OIDC_REDIRECT_URI
  )
  const client = new issuer.Client({
    client_id: process.env.OIDC_CLIENT_ID
  })
  const oidcParams = {
    redirect_uri: process.env.OIDC_REDIRECT_URI,
    scope: process.env.OIDC_SCOPE
  }

  const app = express()

  app.use(logger('dev'))

  app.use(express.urlencoded({ extended: false }))

  app.use(cookieParse())

  passport.use(
    'oidc',
    new Strategy(
      {
        client,
        params: oidcParams,
        passReqToCallback: false,
        usePKCE: true
      },
      (tokenset, userinfo, done) => {
        log.debug('tokenset %o', tokenset)
        log.debug('access_token %o', tokenset.access_token)
        log.debug('id_token %o', tokenset.id_token)
        log.debug('claims %o', tokenset.claims)
        log.debug('userinfo %o', userinfo)
        return done(null, userinfo)
      }
    )
  )

  passport.serializeUser((user, done) => {
    done(null, user)
  })

  passport.deserializeUser((obj, done) => {
    done(null, obj)
  })

  app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: true
    })
  )

  app.use(passport.initialize())
  app.use(passport.session())

  const skipPath = process.env.OIDC_SKIP_PATH
  const skip = skipPath ? skipPath.split(':') : []
  log.debug('skip path: %o', skip)

  app.use('/', (req, res, next) => {
    for (const path of ['/healthz', '/oidc']) {
      if (req.path.startsWith(path)) {
        next()
        return
      }
    }
    for (const path of skip) {
      if (req.path.startsWith(path)) {
        log.info('Auth Skip: %s', req.path)
        res.sendStatus(200)
        return
      }
    }
    if (req.isAuthenticated()) {
      log.info('Auth OK: %s', req.path)
      res.sendStatus(200)
      return
    }
    log.info('Auth NG: %s', req.path)
    res.redirect('/oidc/login')
  })

  app.get(
    '/oidc/login',
    passport.authenticate('oidc', {
      successReturnToOrRedirect: '/'
    })
  )

  app.get(
    '/oidc/callback',
    passport.authenticate('oidc', {
      callback: true,
      successReturnToOrRedirect: '/',
      failureRedirect: '/oidc/login'
    })
  )

  app.get('/oidc/logout', (req, res) => {
    req.logout()
    req.session.destroy()
    res.redirect('/oidc/login')
  })

  app.get('/healthz', (_, res) => {
    res.sendStatus(200)
  })

  return app
}

module.exports = appSetup
