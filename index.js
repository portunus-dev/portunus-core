const async = require('async')
const gpg = require('gpg')


const makeError = ({ message, status }) => {
  const e = new Error(message)
  e.status = status
  return e
}

module.exports.input = (req, _, next) => {
  const { project_id, stage = 'default', encrypt } = req.query
  if (project_id == null) {
    return next(makeError({ message: 'Missing project_id', status: 400 }))
  }
  req._portunus = {
    project_id,
    stage,
    encrypt: !req.secure || ['true', '1'].includes((encrypt || '').toLowerCase()),
  }
  return next()
}

module.exports.encrypt = (req, _, next) => {
  const { vars, keys, encrypt } = req._portunus
  if (!vars || !keys.length) {
    return next(makeError({ message: 'Not found', status: 404 }))
  }
  req._portunus.encrypted = false
  if (!encrypt) {
    return next()
  }
  // async import multiple keys
  async.map(keys, (key, cb) => {
    gpg.importKey(key, (e, _, f) => cb(e, f))
  }, (err, fps) => {
    if (err) {
      return next(err)
    }
    // encrypt vars with imported key fingerprints
    gpg.encrypt(
      JSON.stringify(vars),
      fps.map(fp => (['--recipient', fp])).reduce(
        (c, a) => a.concat(c),
        ['--armor'],
      ),
      (err, enc) => {
        if (err) {
          return next(err)
        }
        if (enc) {
          req._portunus = { ...req._portunus, encrypted: true, vars: enc.toString() }
        }
        return next()
      },
    )
  })
}

module.exports.serve = (req, res) => {
  const { encrypted = false, vars = {} } = req._portunus
  return res.status(200).json({ encrypted, vars })
}
