const cookieParser = require('cookie-parser')
const createDebug = require('debug')
const express = require('express')
const expressLayouts = require('express-ejs-layouts')
const session = require('express-session')
const createError = require('http-errors')
const path = require('path')
const logger = require('morgan')
const passport = require('passport')
const { Issuer, Strategy } = require('openid-client')

const log = {
  info: createDebug('a8r-oidc-auth-service:info'),
  debug: createDebug('a8r-oidc-auth-service:debug')
}

function pathMatch(path, paths) {
  for (const p of paths) {
    if (path.startsWith(p)) {
      return true
    }
  }
  return false
}

async function appSetup() {
  log.info('OIDC provider: %s', process.env.OIDC_PROVIDER)
  const issuer = await Issuer.discover(process.env.OIDC_PROVIDER)

  const root = process.env.KUBECTL_PAGE_PATH

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
  const enableBearerIdToken = !!process.env.ENABLE_BEARER_ID_TOKEN

  const app = express()

  app.set('views', path.join(__dirname, 'views'))
  app.set('view engine', 'ejs')

  app.use(
    logger('dev', {
      skip: req => req.path === '/healthz'
    })
  )

  app.use(express.urlencoded({ extended: false }))

  app.use(cookieParser())

  app.use(express.static(path.join(__dirname, 'public')))

  app.use(expressLayouts)
  app.set('layout extractScripts', true)
  app.set('layout extractStyles', true)

  passport.use(
    'oidc',
    new Strategy(
      {
        client,
        params: oidcParams,
        passReqToCallback: true,
        usePKCE: true
      },
      (req, tokenset, userinfo, done) => {
        log.debug('tokenset %o', tokenset)
        log.debug('userinfo %o', userinfo)
        // store id token to construct Authorization header later
        req.session.idToken = tokenset.id_token
        // store userinfo and refresh token to show kubectl config later
        req.session.userinfo = userinfo
        req.session.refreshToken = tokenset.refresh_token
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

  const skipPath = (process.env.OIDC_SKIP_PATH || '').split(':')
  log.info('Skip path: %o', skipPath)

  const kubeApiPath = (process.env.KUBE_API_PATH || '').split(':')
  log.info('Kubernetes API path: %o', kubeApiPath)

  app.use('/', (req, res, next) => {
    if (pathMatch(req.path, ['/healthz', '/oidc'])) {
      // These paths are handled by this app and do not require auth
      next()
    } else if (pathMatch(req.path, skipPath)) {
      log.info('Auth Skip: %s', req.path)
      res.sendStatus(200)
    } else if (req.isAuthenticated()) {
      log.info('Auth OK: %s', req.path)
      if (enableBearerIdToken) {
        res.append('Authorization', `Bearer ${req.session.idToken}`)
      }
      if (pathMatch(req.path, ['/kubectl', '/assets'])) {
        // These paths are handled by this app
        next()
      } else {
        res.sendStatus(200)
      }
    } else if (pathMatch(req.path, kubeApiPath)) {
      // Let kube-apiserver auth this
      res.sendStatus(200)
    } else {
      log.info('Auth NG: %s', req.path)
      res.redirect('/oidc/login')
    }
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

  app.get('/kubectl', (req, res) => {
    res.locals = {
      root: root.replace(/\/$/, ''),
      title: process.env.TITLE || 'kubectl Configuration',
      username: req.session.userinfo.preferred_username,
      idToken: req.session.idToken,
      refreshToken: req.session.refreshToken,
      provider: process.env.OIDC_PROVIDER,
      clientId: process.env.OIDC_CLIENT_ID,
      clusterName: process.env.CLUSTER_NAME,
      kubeApiUrl: process.env.KUBE_API_URL,
      kubectlContext: process.env.KUBECTL_CONTEXT
    }
    res.render('kubectl')
  })

  app.get('/healthz', (_, res) => {
    res.sendStatus(200)
  })

  // Catch 404 and forward to error handler
  app.use((_, __, next) => {
    next(createError(404))
  })

  // Error handler
  // eslint-disable-next-line
  app.use((err, req, res, _) => {
    res.status(err.status || 500)
    res.locals = {
      root: root.replace(/\/$/, ''),
      env: req.app.get('env'),
      title: 'Error',
      message: err.message,
      error: err
    }
    res.render('error')
  })

  return app
}

module.exports = appSetup
