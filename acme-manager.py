#!/usr/bin/env python

import sys, argparse, logging, textwrap, os, pwd, grp, subprocess, ConfigParser, shutil, acme_tiny, tempfile, itertools
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"
#DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
CA_CHAIN = "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem"
CA_CRT = "https://ssl-tools.net/certificates/dac9024f54d8f6df94935fb1732638ca6ad77c13.pem"

def gid(_gid):
    """Returns a gid, given a string that is either the gid number or the group name."""
    try:
        return int(_gid)
    except ValueError:
        try:
            return grp.getgrnam(_gid)[2]
        except KeyError:
            raise ValueError("Unrecognized gid '%s'" % _gid)

def uid(_uid):
    """Returns a uid, given a string that is either the uid number or the user name."""
    try:
        return int(_uid)
    except ValueError:
        try:
            return pwd.getpwnam(_uid)[2]
        except KeyError:
            raise ValueError("Unrecognized uid '%s'" % _uid)

def _mode(f, mode=0750):
    """Wraps a function in umask calls to enforce permissions on file creation"""
    umask = 0777 ^ mode
    def inner(*args, **kwds):
        oldmask = os.umask(umask)
        f(*args, **kwds)
        os.umask(oldmask)
    return inner

def _dump_string_list(string_list, file):
    """Dumps a list of strings to a file (adds newlines)"""
    with open(file, 'w') as fh:
        for line in string_list:
            fh.write(line + "\n")

def _load_string_list(file):
    """Loads a list of strings from a file (strips newlines)"""
    with open(file, 'r') as fh:
        return [line.strip() for line in fh]

def _dump_bytes(data, file):
    """Dumps the given data contents to the given file"""
    with open(file, 'wb') as fh:
        fh.write(data)

def _load_bytes(file):
    """Loads the contents of a file"""
    with open(file, 'rb') as fh:
        return fh.read()

def _build_certificate_structure(args):
    """Builds the folder structure of a certificate definition"""
    path = args.path + '/' + args.name
    if not os.path.exists(path):
        os.mkdir(path, 0770)
    os.chmod(path, 0770)
    os.chown(path, -1, args.gid)

def _store_certificate_domains(args, log=LOGGER):
    """Stores the list of domains covered by a certificate"""
    path = args.path + '/' + args.name + '/hosts'
    _mode(_dump_string_list, 0644)(args.host, path)
    os.chmod(path, 0644)
    log.debug("Dumped %d hosts for certificate '%s'" % (len(args.host), args.name))

def _load_certificate_domains(args, log=LOGGER):
    """Loads the list of domains covered by a certificate"""
    path = os.path.join(args.path, args.name, 'hosts')
    if not os.path.isfile(path):
        log.error("Missing hosts file '%s'." % path)
        sys.exit(1)
    return _load_string_list(path)

def _generate_domain_key(args, log=LOGGER):
    """Generates the private key for a domain certificate"""
    path = os.path.join(args.path, args.name, 'domain.key')
    # openssl genrsa 4096 > domain.key
    proc = subprocess.Popen(["openssl", "genrsa", "4096"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    _mode(_dump_bytes, 0640)(out, path)
    os.chmod(path, 0640)

def _generate_domain_csr(args, log=LOGGER):
    key = os.path.join(args.path, args.name, 'domain.key')
    sslargs = ['openssl', 'req', '-new', '-sha256', '-key', key, '-subj']

    domains = _load_certificate_domains(args)
    if not domains:
        log.warn('There are no hosts associated to this domain yet.')
        return

    with tempfile.NamedTemporaryFile() as conf:
        data = _load_bytes(args.openssl_cnf)

        if len(domains) == 1:
            # for a single domain
            # openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr
            sslargs.append('/CN=' + domains[0])

        else:
            # for multiple domains (use this one if you want both www.yoursite.com and yoursite.com)
            # openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) > domain.csr
            sslargs.extend(['/', '-reqexts', 'SAN'])
            data += "\n[SAN]\nsubjectAltName=" + \
                ','.join("DNS:" + domain for domain in domains)

        conf.write(data)
        conf.flush()
        sslargs.extend(['-config', conf.name])

        path = os.path.join(args.path, args.name, 'domain.csr')
        proc = subprocess.Popen(sslargs,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()

    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    _mode(_dump_bytes, 0644)(out, path)
    os.chmod(path, 0644)

def _list_certificates(args, log=LOGGER):
    """Lists all setup certificates"""

    def is_certificate(path, name):
        """Checks is name is a certificate setup under the given path"""
        fullname = os.path.join(path, name)
        return os.path.isdir(fullname) and os.path.isfile(os.path.join(fullname, 'hosts'))

    path = args.path
    return [name for name in os.listdir(path) if is_certificate(path, name)]

def _get_signed_certificate(name, args, log=LOGGER):
    """Gets a signed certificate (using acme-tiny)"""
    account = os.path.join(args.path, 'account.key')
    csr = os.path.join(args.path, name, 'domain.csr')
    crt = os.path.join(args.path, name, 'domain.crt')
    out = acme_tiny.get_crt(account, csr, args.acme_dir, log, args.ca)
    _mode(_dump_bytes, 0640)(out, crt)
    os.chmod(crt, 0640)

def _build_certificate_bundles(name, args, log=LOGGER):
    """Builds assorted crt bundles"""

    def bundle(parts, bundle_name, mode=0640):
        bundle = os.path.join(args.path, name, bundle_name)
        _mode(_dump_bytes, mode)("\n".join(parts), bundle)
        os.chmod(bundle, mode)

    resp = urlopen(CA_CHAIN)
    if resp.code != 200:
        raise IOError("Cannot get intermediate certificate. HTTP response code: '%s'" % resp.code)
    intermediate = resp.read()

    resp = urlopen(CA_CRT)
    if resp.code != 200:
        raise IOError("Cannot get root certificae. HTTP response code: '%s'" % resp.code)
    root = resp.read()

    crt = _load_bytes(os.path.join(args.path, name, 'domain.crt'))

    bundle([intermediate], 'intermediate.crt', 0644)
    bundle([root], 'root.crt', 0644)
    bundle([crt, intermediate], 'domain.intermediate.crt', 0640)
    bundle([intermediate, crt], 'intermediate.domain.crt', 0640)
    bundle([crt, intermediate, root], 'domain.intermediate.root.crt', 0640)
    bundle([intermediate, root], 'intermediate.root.crt', 0644)
    bundle([root, intermediate], 'root.intermediate.crt', 0644)
    bundle([root, intermediate, crt], 'root.intermediate.domain.crt', 0640)


def init(args, log=LOGGER):
    """Initializes the acme system"""
    path, create = args.path + '/account.key', True
    if os.path.exists(path):
        if args.force:
            log.info("Warning: re-creating account key '%s'" % path)
        else:
            log.error("Error: account key '%s' already exists." % path)
            create = False

    if create:
        # openssl genrsa 4096 > account.key
        proc = subprocess.Popen(["openssl", "genrsa", "4096"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        _mode(_dump_bytes, 0640)(out, path)

    os.chmod(path, 0640)
    os.chown(path, -1, args.gid)

def setup(args, log=LOGGER):
    """Creates a new certificate definition"""
    _build_certificate_structure(args)
    _store_certificate_domains(args)
    _generate_domain_key(args)
    _generate_domain_csr(args)
    log.info("Added certificate '%s' covering domains: %s" % (args.name, ', '.join(args.host)))

def remove(args, log=LOGGER):
    path = args.path + '/' + args.name
    shutil.rmtree(path)
    log.info("Removed certificate '%s'." % args.name)

def renew(args, log=LOGGER):
    def _renew(name):
        _get_signed_certificate(name, args)
        _build_certificate_bundles(name, args)
        log.info("Renewed certificate '%s'" % name)
        return True

    names = args.name if args.name else _list_certificates(args)
    return all(_renew(cert) for cert in names)

def _sanity_check(args, log=LOGGER):
    if not os.path.isdir(args.path):
        log.error("The specified acme configuration folder path '%s' does not exist." % args.path)
        sys.exit(1)

    if not os.access(args.openssl, os.X_OK):
        log.error("Openssl binary '%s' does not exist or is not executable." % args.openssl)
        sys.exit(1)

    if not os.access(args.openssl_cnf, os.R_OK):
        log.error("Openssl configuration file '%s' does not exist or is not readable." % args.openssl_cnf)
        sys.exit(1)

def _load_config(argv):
    """Loads the configuration (location possibly overriden by the arguments)"""
    # Scan input for config file argument and specified location
    newargs, path = [], None
    for i, arg in enumerate(argv):
        if arg[:6] != '--conf':
            newargs.append(arg)
        else:
            if arg == '--conf':
                path = argv.pop(i+1)
            elif arg[6] == '=':
                path = arg[7:]

    # Load config file and return as paths
    if not path:
        path = '/etc/acme/acme.conf'

    if not os.access(path, os.R_OK):
        LOGGER.warning("Configuration file '%s' does not exist. Using defaults." % path)

    else:
        parser = ConfigParser.SafeConfigParser()
        parser.read(path)
        for k,v in parser.items('acme'):
            newargs = ['--'+k, v] + newargs
        newargs = ['--conf', path] + newargs

    return newargs

def main(argv):
    argv = _load_config(argv)
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the management of acme certificates in a server.
            """)
    )
    parser.add_argument("--conf", default='/etc/acme/acme.conf', help='path to your acme configuration file')
    parser.add_argument("--path", default='/etc/acme', help="path to your acme configuration folder")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument('--uid', default='acme', type=uid, help='uid/username of the acme user')
    parser.add_argument('--gid', default='acme', type=gid, help='gid/group of the acme group')
    parser.add_argument('--openssl', default='/usr/bin/openssl', help='path to the openssl binary')
    parser.add_argument('--openssl-cnf', default='/usr/lib/ssl/openssl.cnf', help='path to the openssl configuration file')
    subparsers = parser.add_subparsers(title='actions', help='Action to perform')

    parser_init = subparsers.add_parser('init', help='Initializes your ACME account')
    parser_init.add_argument('--force', dest='force', action='store_true', help='Force account key re-creation if it already exists.')
    parser_init.set_defaults(func=init)

    parser_setup = subparsers.add_parser('setup', help='Setup a certificate')
    parser_setup.add_argument('--force', dest='force', action='store_true', help='Force certificate key overwrite if it already exists')
    parser_setup.add_argument('name', help="Certificate name")
    parser_setup.add_argument('host', nargs='+', help="Host name(s) covered by this certificate")
    parser_setup.set_defaults(func=setup)

    parser_remove = subparsers.add_parser('remove', help='Remove a certificate')
    parser_remove.add_argument('name', help="Certificate name")
    parser_remove.set_defaults(func=remove)

    parser_renew = subparsers.add_parser('renew', help='Renew certificates')
    parser_renew.add_argument("--acme-dir", default='/var/www/acme', help="path to the .well-known/acme-challenge/ directory")
    parser_renew.add_argument("--ca", default=DEFAULT_CA, help="certificate authority, default is Let's Encrypt")
    parser_renew.add_argument('name', nargs='*', help="Certificate to renew (all certificates will be renewed if none is specified)")
    parser_renew.set_defaults(func=renew)

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)

    _sanity_check(args)
    args.func(args)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])