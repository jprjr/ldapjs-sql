var Ldap = require('ldapjs');
var parseDN = Ldap.parseDN;
var Sql = require('mysql');
var crypto = require('crypto');
var fs = require('fs');
var EventEmitter = require("events").EventEmitter;

function SqlConnection(config) {

    var sql_connection = Sql.createConnection(config);
    var running_queries = 0;

    this.connect = function() {
        sql_connection.connect(function(err) {
            if(err) {
                console.log("Error connecting to db: ", err);
                process.exit(1);
            }
        });
        sql_connection.on('error', function(err) {
            if(err.code === 'PROTCOL_CONNECTION_LOST') {
                connect();
            } else {
                throw err;
            }
        });
    }

    this.query = function(sqlquery, callback) {
        sql_connection.query(sqlquery,callback);
    }
    this.queries = function() {
        return running_queries;
    }
    this.start_query = function() {
        running_queries += 1;
    }
    this.done_query = function() {
        running_queries -= 1;
    }

    return this;
}

function Leaf(dn_string,attributes) {
    this.leaf = {};
    this.children = [];

    this.leaf.dn = parseDN(dn_string).spaced(false);
    this.leaf.attributes = attributes;
    this.leaf.attributes.hassubordinates = 'FALSE';

    this.userpassword = false;
    if(this.leaf.attributes.userpassword !== undefined) {
        if(this.leaf.attributes.userpassword.length > 0) {
            this.checkPassword = new PasswordCheck(this.leaf.attributes);
            this.userpassword = true;
        }
        delete this.leaf.attributes.userpassword;
    }

    this.toString = function() {
        var string = this.leaf.dn.toString();
        Object.keys(this.leaf.attributes).forEach(function(k) {
            string = string +' '+ k +':'+attributes[k];
        });
        string = string +' userpassword:'+this.userpassword;
        return string;
    }

    this.add_child = function(child) {
        this.children.push(child);
        this.leaf.attributes.hassubordinates = 'TRUE';
    }

    this.update_refs = function(leafs) {
        var parent_leaf = this.leaf;
        if(this.leaf.attributes.uniquemember !== undefined &&
           Array.isArray(this.leaf.attributes.uniquemember) ) {
            this.leaf.attributes.uniquemember.forEach(function(k) {
                if(leafs[k] !== undefined) {
                    if(leafs[k].leaf.attributes.memberof === undefined) {
                        leafs[k].leaf.attributes.memberof = [];
                    }
                    if(leafs[k].leaf.attributes.memberof.indexOf(parent_leaf.dn.toString()) === -1) {
                        leafs[k].leaf.attributes.memberof.push(parent_leaf.dn.toString());
                    }
                }
            });
        }
        if(this.leaf.attributes.seealso !== undefined) {
            if(leafs[this.leaf.attributes.seealso] !== undefined) {
                this.leaf.attributes = merge_attr(this.leaf.attributes, leafs[this.leaf.attributes.seealso].leaf.attributes);
            }
        }
        if(this.children.length > 0) {
            this.children.forEach(function(k) {
                k.update_refs(leafs);
            });
        }
    }

    this.search = function(req,res,next) {
        var searchAttr = lower_attr(this.leaf.attributes);
        if( (req.scope === 'sub' ) ||
            (req.scope === 'one'  && req.dn.parentOf(this.leaf.dn)) ||
            (req.scope === 'base' && req.dn.equals(this.leaf.dn)) ) {
            if(req.filter.matches(searchAttr)) {
                res.send(this.leaf);
            }
        }
        if( (req.scope === 'sub') ||
            (req.scope === 'one' && req.dn.equals(this.leaf.dn)) ) {
            if(this.children.length > 0) {
                this.children.forEach(function(k) {
                    k.search(req,res,next);
                });
            }
        }
        if( req.dn.equals(this.leaf.dn) ) {
            res.end();
            return next();
        }
    }
    return this;
}

function LowercaseFilter(filter) {
    if(filter.type === 'substring') {
        if(filter.attribute === 'memberof') {

        }
        else {
            filter.any = filter.any.map(function(currentValue) { return currentValue.toLowerCase();});
            if(filter.initial !== undefined) {
                filter.initial = filter.initial.toLowerCase();
            }
            if(filter.final !== undefined) {
                filter.final = filter.final.toLowerCase();
            }
        }
    }
    if(filter.type === 'and') {
        filter.filters = filter.filters.map(function(currentValue) { return LowercaseFilter(currentValue) ; } );
    }
    if(filter.type === 'or') {
        filter.filters = filter.filters.map(function(currentValue) { return LowercaseFilter(currentValue) ; } );
    }
    return filter;
}

function SqlBranch(branches) {
    var branches = {};
}


function PasswordCheck(attrs) {
    if(attrs.pwdaccountlockedtime !== undefined) {
        // account locked out, so just return false
        return function(attempt) {
            return false;
        }
    }

    var matches;
    var password = attrs.userpassword;
    matches = password.match(/^(\{.+\})/);
    if(matches === null) {
        return function(attempt) {
            if(password !== attempt) {
                return false;
            }
            return true;
        };
    }
    else {
        return function(attempt) {
            var hashmethod = matches[1].replace('{','').replace('}','').toLowerCase();
            var hashedpass = password.replace(matches[1],'');
            if(hashmethod === 'sha') {
                hashmethod = 'sha1';
            }
            var hashedattempt = crypto.createHash(hashmethod).update(attempt).digest('base64');
            if(hashedpass !== hashedattempt) {
                return false;
            }
            return true;
        };
    }
}

function LdapSql(config_file) {

    var ssl = {};
    this.sql_conn;

    this.server;

    var loadconfig = function() {
        ssl.certificate;
        ssl.key;

        var config = JSON.parse(fs.readFileSync(config_file).toString());
        if(config.ldap.ssl_cert !== undefined) {
            ssl.certificate = fs.readFileSync(config.ldap.ssl_cert).toString();
        }
        if(config.ldap.ssl_cert !== undefined) {
            ssl.key = fs.readFileSync(config.ldap.ssl_key).toString();
        }

        server = Ldap.createServer(ssl);
        sql_conn = new SqlConnection(config.sql);

        server.listen(config.ldap.port, function() {
            console.log("LDAP server listening at %s", server.url);
        });

        var refresh_function = function() {
            var leafs = {};
            var leaf;
            var ee = new EventEmitter();
            ee.on("leafReady", function() {
                server.bind(config.branches[0].branch,BindFunction(leafs)); 
                server.search(config.branches[0].branch,SearchFunction(leafs));
            });
            leaf = RefreshMethod(config.branches[0],sql_conn,leafs,config.branches[0].branch, ee);
        }

        refresh_function();
        setInterval(refresh_function,config.sql.timeout);
    }

    loadconfig();
}

function SearchFunction(leafs) {
    return function(req,res,next) {
        var bind_dn = req.connection.ldap.bindDN.toString();
        var accountObj = leafs[bind_dn];
        if(accountObj === undefined) {
            return next(new Ldap.InsufficientAccessRightserror());
        }
        var searchObj = leafs[req.dn.spaced(false).toString()];
        if( searchObj === undefined) {
            return next(new Ldap.NoSuchObjectError);
        }
        req.filter = LowercaseFilter(req.filter);
        searchObj.search(req,res,next);
    }
}

function BindFunction(leafs) {
    return function(req,res,next) {
        var accountObj = leafs[req.dn.spaced(false).toString()];
        if(accountObj === undefined) {
            return next(new Ldap.InsufficientAccessRightsError());
        }
        if(! accountObj.userpassword) {
            return next(new Ldap.NoSuchAttributeError('userpassword'));
        }
        if(! accountObj.checkPassword(req.credentials.toString()) ) {
            return next(new Ldap.InvalidCredentialsError());
        }
        res.end();
        return next();
    }
}

function lower_attr(attr1) {
    var attr = {};
    Object.keys(attr1).forEach(function(k) {
        if(attr1[k] !== undefined && attr1[k] !== null) {
            if(k.toLowerCase() === 'memberof') {
                    attr[k.toLowerCase()] = attr1[k];
            }
            else {
                if(Array.isArray(attr1[k])) {
                    attr[k.toLowerCase()] = attr1[k].map(function(currentValue) { currentValue.toLowerCase(); } );
                }
                else {
                    if( typeof attr1[k] === 'string' ) {
                        attr[k.toLowerCase()] = attr1[k].toLowerCase();
                    }
                    else {
                        attr[k.toLowerCase()] = attr1[k];
                    }
                }
            }
        }
    });
    return attr;
}

function merge_attr(attr1, attr2) {
    var attr = {};
    Object.keys(attr1).forEach(function(k) {
        if(attr1[k] !== undefined && attr1[k] !== null) {
            if(Array.isArray(attr1[k])) {
                attr[k.toLowerCase()] = Array();
                attr1[k].forEach(function(l) {
                    attr[k.toLowerCase()].push(l);
                });
            }
            else {
                attr[k.toLowerCase()] = attr1[k];
            }
        }
    });
    Object.keys(attr2).forEach(function(k) {
        if(attr2[k] !== undefined && attr2[k] !== null) {
            if(Array.isArray(attr[k.toLowerCase()])) {
                if(! Array.isArray(attr2[k]) ) {
                    attr[k.toLowerCase()].push(attr2[k]);
                }
            }
            else {
                if(Array.isArray(attr2[k])) {
                    if(attr[k.toLowerCase()] === undefined) {
                        attr[k.toLowerCase()] = Array();
                    }
                    if(typeof attr[k.toLowerCase()] === 'string') {
                        var tmp = attr[k.toLowerCase()];
                        attr[k.toLowerCase()] = Array();
                        attr[k.toLowerCase()].push(tmp);
                    }
                    attr2[k].forEach(function(l) {
                        attr[k.toLowerCase()].push(l);
                    });
                }
                else {
                    attr[k.toLowerCase()] = attr2[k];
                }
            }
        }
    });
    return attr;
}

function SqlChildrenPivot(config,sql_conn,leafs,parent_leaf,root_branch, ee) {
    var sql_query = fs.readFileSync(config.queryfile).toString();
    sql_conn.start_query();
    sql_conn.query(sql_query, function(err, rows, fields) {
        var temp_leafs = {};
        var temp_arrays = {};
        for(var row in rows) {
            var rdn = fields[0].name +'=' + rows[row][fields[0].name] + ',' + parent_leaf.leaf.dn.toString();
            var attr = merge_attr(rows[row],config.attributes);
            config.pivot_links.forEach(function(k) {
                delete attr[k.dn.toLowerCase()];
                var link_rdn = k.dn.toLowerCase() + '=' + rows[row][k.dn] + ',' + k.branch;
                if(temp_arrays[rdn] === undefined) {
                    temp_arrays[rdn] = {};
                    temp_arrays[rdn][k.attr] = [];
                }
                temp_arrays[rdn][k.attr].push(link_rdn);
            });
            if(temp_leafs[rdn] === undefined) {
                temp_leafs[rdn] = new Leaf(rdn,attr);
            }
        }
        Object.keys(temp_leafs).forEach(function(l) {
            t_leaf = temp_leafs[l];
            Object.keys(temp_arrays[t_leaf.leaf.dn.toString()]).forEach(function(a) {
                t_leaf.leaf.attributes[a] = temp_arrays[t_leaf.leaf.dn.toString()][a];
             });
            parent_leaf.add_child(t_leaf);
            leafs[t_leaf.leaf.dn.toString()] = t_leaf;
        });
        sql_conn.done_query();
        if(sql_conn.queries() === 0) {
            var root_leaf = leafs[root_branch];
            root_leaf.update_refs(leafs);
            ee.emit("leafReady");
        }
    });
}

function SqlChildren(config,sql_conn,leafs,parent_leaf,root_branch, ee) {
    var sql_query = fs.readFileSync(config.queryfile).toString();
    sql_conn.start_query();
    sql_conn.query(sql_query, function(err, rows, fields) {
        for(var row in rows) {
            var rdn = fields[0].name +'=' + rows[row][fields[0].name] + ',' + parent_leaf.leaf.dn.toString();
            var attr = merge_attr(rows[row],config.attributes);
            if(config.links !== undefined && Array.isArray(config.links)) {
                config.links.forEach(function(k) {
                    delete attr[k.dn];
                    attr[k.attr.toLowerCase()] = parseDN(k.dn.toLowerCase() + '=' + rows[row][k.dn] + ',' + k.branch).spaced(false).toString();
                });
            }
            var leaf = new Leaf(rdn,attr);
            leafs[leaf.leaf.dn.toString()] = leaf;
            parent_leaf.add_child(leaf);
        }
        sql_conn.done_query();
        if(sql_conn.queries() === 0) {
            var root_leaf = leafs[root_branch];
            root_leaf.update_refs(leafs);
            ee.emit("leafReady");
        }
    });
    return;
}

function RefreshMethod(config,sql_conn,leafs,root_branch, ee) {
    var leaf;
    if(config.method === "static" ) {
        var attr = merge_attr({},config.attributes);
        leaf = new Leaf(config.branch,attr);
        leafs[leaf.leaf.dn.toString()] = leaf;
    }

    if(Array.isArray(config.children)) {
        for(var child in config.children) {
            leaf.add_child(RefreshMethod(config.children[child],sql_conn,leafs,root_branch,ee));
        }
    }
    else {
        if(config.children !== undefined && config.children.method === "sql" ) {
            if(config.children.pivot_links !== undefined && Array.isArray(config.children.pivot_links)) {
                SqlChildrenPivot(config.children,sql_conn,leafs,leaf,root_branch, ee);
            }
            else {
                SqlChildren(config.children,sql_conn,leafs,leaf,root_branch, ee);
            }
        }
    }
    return leaf;
}


module.exports = LdapSql;
