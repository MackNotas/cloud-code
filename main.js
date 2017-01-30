//
//  Métodos de encriptação usando algoritmo AES-256.
//  Lembre-se: Se mudar qualquer dígito da senha ou o algoritmo de enc, é necessário resetar a coluna passwordEnc da table USER
//

var crypto        = require('crypto');
var algorithmType = 'aes-256-ctr';
var passwordCrypto = 'key';

//
//  @Recebe uma string simples
//  @Retorna uma string simples encriptada
//
function encrypt(text){
  var cipher = crypto.createCipher(algorithmType,passwordCrypto)
  var crypted = cipher.update(text,'utf8','hex')
  crypted += cipher.final('hex');
  return crypted;
}

//
//  @Recebe uma string encriptada
//  @Retorna uma string simples
//
function decrypt(text){
  var decipher = crypto.createDecipher(algorithmType,passwordCrypto)
  var dec = decipher.update(text,'hex','utf8')
  dec += decipher.final('utf8');
  return dec;
}

//
//  Função de encriptar a senha do usuário. Método recebe um PFUser (pois pra editar um Usuer ele precisa estar logado), e
//  a senha que ele digitou CRUA. Depois faz a encriptação e adiciona no banco na tabela passwordEnc.
//  Retorna um BOOL relatando a situação.
//  @request.params.passToBeEncrypted = SENHA DO USUARIO CRUA
//  @request.user = PFUser logado (SE O USUARIO NAO ESTIVER LOGADO, ISSO NAO EH RECEBIDO!)
//
Parse.Cloud.define("encryptPassWithPFUserAtSignUp", function(request, response) {
// Parse.Cloud.useMasterKey();

var passToBeEncrypted = request.params.passToBeEncrypted;
var user = request.user;
// console.log("pass to be: " + passToBeEncrypted);
// console.log("User request:" + request.user.username);

if (passToBeEncrypted && request.user) {
  var passEncrypted = encrypt(passToBeEncrypted);
  // console.log("Pass encryped: " + passEncrypted);
  if (passEncrypted) {
    request.user.set('passwordEnc', passEncrypted);
    request.user.save(null, {
      success: function(object) {
        // console.log('User saved: ' + request.user.username);
        response.success(user.get("name"));
      },
      error: function(object, error) {
        console.log('Failed to save User: ' + request.user.username + ' with message: ' + error.message);
        response.error('Failed to save User: ' + request.user.username + ' with message: ' + error.message);
      }
    });
  };
  }
});

//
//  Funcao de verificar se o a senha do usuário cadastrada no parse é válida no TIA do mackenzie
//  @Recebe como parametro apenas o PFUser, que espera-se que já contenha uma senha encriptada salva
//  @Retorna o JSON fornecido pelo WS (Login: true, false)
//
Parse.Cloud.define("verifyPFUserAuthOnWebService", function(request, response) {

var passToBeDencrypted = request.user.get('passwordEnc');
var user = request.user;
// console.log("pass to be: " + passToBeDencrypted);
// console.log("User request:" + request.user.get('username'));

if (passToBeDencrypted && user) {
var passDecrypted = decrypt(passToBeDencrypted);
// console.log("Pass decryped: " + passDecrypted);

if (passDecrypted) {

  var urlWebService = 'https://tia-webservice.herokuapp.com/tiaLogin_v2.php';

  Parse.Cloud.httpRequest({
    method: 'POST',
    url: urlWebService,
    headers: {
      'Content-Type': 'application/json;charset=utf-8',
      'ContentType': 'application/json'
    },
    body: {
      'userTia' : request.user.get('username'),
      'userPass' : passDecrypted,
      'userUnidade' : request.user.get('unidade'),
      'tipo' : '4'
    },
    success: function(httpResponse) {
       var jsonResponse = JSON.parse(httpResponse.text)
       if ("login" in jsonResponse) {
          response.success(jsonResponse);
       }
       else {
        var jsonError = '{"tiaDown" : true, "status" :"' + httpResponse.status + '", "response" : ' + JSON.stringify(httpResponse.text) + '}';
        console.log(jsonError);
        response.error(JSON.parse(jsonError));
       }
    },
    error: function(httpResponse) {
      response.error('Request failed with response code ' + httpResponse.status);
    }
  });
}
}
});

//
//  @Recebe dois params:
//    userTia = TIA do usuario que está se registrando
//    userPass = senha
//    userUnidade = unidade do usuario
//
//  Ela verifica no WebService se o Tia e Senha informados são validos.
//  @Retorna o JSON fornecido pelo WS (Login: true, false)
//
Parse.Cloud.define("verifyTiaBeforeSignUpWithTiaAndPass", function(request, response) {
console.log(request);
var TiaToBeVerified = request.params.userTia;
var passToBeVerified = request.params.userPass;
var unidade = request.params.userUnidade ? request.params.userUnidade : '001';

var urlWebService = 'https://tia-webservice.herokuapp.com/tiaLogin_v2.php';

Parse.Cloud.httpRequest({
   method: 'POST',
   url: urlWebService,
    headers: {
      'Content-Type': 'application/json;charset=utf-8',
      'ContentType': 'application/json'
    },
    body: {
      'userTia' : TiaToBeVerified,
      'userPass' : passToBeVerified,
      'userUnidade' : unidade,
      'tipo' : '4'
    },
   success: function(httpResponse) {
      var jsonResponse = JSON.parse(httpResponse.text)
      if ("login" in jsonResponse) {
         response.success(jsonResponse);
      }
      else {
       var jsonError = '{"tiaDown" : true, "status" :"' + httpResponse.status + '", "response" : ' + JSON.stringify(httpResponse.text) + '}';
       console.log(jsonError);
       response.error(JSON.parse(jsonError));
      }
   },
   error: function(httpResponse) {
     response.error('Request failed with response code ' + httpResponse.status);
   }
 });
});

//
//  @Recebe o TIA e Pass do usuário, levando em conta que o usuário já deve estar registrado no parse.
//  Atualiza a senha normal, e a encriptada.
//  Só chame esse método apos ter validado a existencia do usuário no banco do Parse.
//  @Retorna uma mensagem de sucesso, ou de falha ao atualizar.
//

Parse.Cloud.define("updateRegisteredUserPasswordWithTiaAndPass", function(request, response) {

Parse.Cloud.useMasterKey();

var query = new Parse.Query(Parse.User);
var passToBeEncrypted = request.params.userPass;
var unidade = request.params.unidade;

query.equalTo("username", request.params.userTia);
query.find({
  success: function(results) {
    var userObject = results[0];
    var passEncrypted = encrypt(passToBeEncrypted);
    userObject.set('passwordEnc', passEncrypted);
    userObject.set('password', passToBeEncrypted);
    userObject.set('unidade', unidade)
    userObject.save(null, {
      success: function(object) {
        // console.log('User saved: ' + request.user.username);
        response.success("true");
      },
      error: function(object, error) {
        console.log('Failed to save User: ' + userObject.username + ' with message: ' + error.message);
        response.error('Failed to save User: ' + userObject.username + ' with message: ' + error.message);
      }
   });
},
  error: function(error) {
    alert("Error: " + error.code + " " + error.message);
  }
});
});

//
//  O método que verifica se há novas notas no TIA, por meio de uma JOB
//    Regras:
//      * Há um limite máximo de 15s para o Heroku devolver as notas, caso contrario, o parse cencelará a request do grupo
//      * As requests são divididas em grupos com 9 usuários cada por ordem de created
//      * A medida que o WS devolve as requests, o Parse vai fazendo as condições necess´rias para envio. Não há uma ordem de push.
//      * Se o usuário optar por receber apenas uma vez a nota, o parse irá salvar o JSON recebido no banco no usuário
//      * O parse tem limite de 15 minutos para uma Job. Não se sabe o limite da nossa job.
//

Parse.Cloud.job("pushNota", function(request, status) {

    Parse.Cloud.httpRequest({method: 'GET', url: 'http://tia-webservice.herokuapp.com/', body: {}});
  
    Parse.Cloud.useMasterKey();
    var Notas = Parse.Object.extend("Notas");
    var query = new Parse.Query(Notas);
    var nomeDasNotas = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "SUB", "PARTC.", "MI", "PF", "MF"];

    query.include("user");
    query.find({
        success: function(results) {
            var usersDictionary = {};
            var tiaArray = new Array();
            var passArray = new Array();
            var unidadeArray = new Array();
            var usuariosDoBanco = results;

            for (var i = 0; i < results.length; i++) {
                tiaArray[i] = results[i].get('user').get('username');
                passArray[i] = decrypt(results[i].get('user').get('passwordEnc'));
                unidadeArray[i] = results[i].get('user').get('unidade') ? results[i].get('user').get('unidade') : "001";
            };

            var usuarios_por_request = 3;

            console.log("Rodando Push Notas - Total Usuarios: " + tiaArray.length + " - " + usuarios_por_request + "/request");

            for (var i = 0; i < tiaArray.length; i += usuarios_por_request) {

                var jsonTiaTotal = JSON.stringify(tiaArray.slice(i, i + usuarios_por_request));
                var jsonPassTotal = JSON.stringify(passArray.slice(i, i + usuarios_por_request));
                var jsonUnidadeTotal = JSON.stringify(unidadeArray.slice(i, i + usuarios_por_request));
                // console.log('Letra i: ' + i + ' JsonTiaTotalSizeSclied: ' + jsonTiaTotal);
                Parse.Cloud.httpRequest({
                    method: 'POST',
                    url: 'https://tia-pushwebservice.herokuapp.com/tiaPushJob.php',
                    body: {
                        userTia: jsonTiaTotal,
                        userPass: jsonPassTotal,
                        userUnidade: jsonUnidadeTotal
                    },
                    success: function(httpResponse) {
                        var tiaJsonParsed = JSON.parse(httpResponse.text);
                        // console.log("Response: " + httpResponse.text);
                        // console.log("JsonParsed: " + tiaJsonParsed[0][0]['tia']);
                        // console.log("JsonParsed: " + tiaJsonParsed[0].notas);

                        // console.log(jsonParsed[0].nome);
                        // console.log('JsonParsed Length: ' + tiaJsonParsed.length);

                        for (var w = 0; w < tiaJsonParsed.length; w++) {
                            var jsonUsuario = tiaJsonParsed[w];
                            var tiaParaComparar = tiaJsonParsed[w][0]['tia'];
                            // console.log(tiaParaComparar);
                            //Se o usuario tiver TIA invalido  (sem grade, ex aluno etc...)
                            if (tiaParaComparar == -1) {
                                console.log('Skipping invalid TIA: ' + w);
                                continue;
                            }

                            var hasNovaNota = false;
                            var posicaoUsuarioDoBanco = -1;
                            var notasDoUsuarioDoTia = tiaJsonParsed[w];

                            for (var y = 0; y < usuariosDoBanco.length; y++) {

                                if ((usuariosDoBanco[y].get('user').get('username').localeCompare(tiaParaComparar)) == 0) {

                                    // console.log('Tia: ' + usuariosDoBanco[y].get('user').get('username') + ' matched: ' + tiaParaComparar);
                                    var notasDoUsuarioNoBanco = JSON.parse(usuariosDoBanco[y].get('notaJson'));
                                    var shouldShowNota = usuariosDoBanco[y].get('user').get('showNota');
                                    var shouldSendPushOnce = usuariosDoBanco[y].get('user').get('pushOnlyOnce');
                                    // console.log(shouldSendPushOnce);
                                    // console.log('SHOULDSEND PUSH: ' + shouldSendPushOnce);
                                    // console.log('DebugTIA: materias ' + notasDoUsuarioDoTia[0]['nome']);
                                    // console.log('DebugTIA: full notas ' + notasDoUsuarioDoTia[0]['notas']);
                                    // console.log('DebugBANCO: Materiass: ' + notasDoUsuarioNoBanco[0]['nome']);
                                    // console.log('DebugBANCO: full notas: ' + notasDoUsuarioNoBanco[0]['notas']);

                                    for (var x = 0; x < 15; x++) {
                                        if (!notasDoUsuarioDoTia || !notasDoUsuarioDoTia[x]) {
                                            // console.log('SKIP: Invalid Result TIA: ' + tiaParaComparar + ' notas ' + notasDoUsuarioDoTia);
                                            break;
                                        }
                                        // if (!('notas' in notasDoUsuarioDoTia[x])) {
                                        //   console.log('SKIP: Invalid Result TIA: ' + tiaParaComparar);
                                        //   break;
                                        // }
                                        
                                        //
                                        //  Pule a materia se:
                                        // - Se a materia nao tiver 15 notas (TCC tem 14)
                                        // - A matéria não possuir a key "notas"
                                        //

                                        var shouldSkip = true;

                                        //
                                        //  Alguns JSONs estão bugados no banco, e vem como Undefined.
                                        //  is_object garante que não é Undefined e herda de Object
                                        //  Se for um Object, itera em suas Keys procurando pela key 'notas'
                                        //
                                        if (is_object(notasDoUsuarioNoBanco[x])) {
                                          Object.keys(notasDoUsuarioNoBanco[x]).forEach(function(key) {
                                            if (key == "notas") { shouldSkip = false; }
                                          });
                                        }

                                        if (shouldSkip || notasDoUsuarioNoBanco[x]['notas'].length != 15) {
                                            console.log("Materia Sem NOTAS: " + tiaParaComparar + " " + JSON.stringify(notasDoUsuarioNoBanco[x]));
                                            continue;
                                        }

                                        var notaParaComparar = notasDoUsuarioDoTia[x]['notas'];
                                        var materiaParaComparar = notasDoUsuarioDoTia[x]['nome'];
                                        var materiaDoBanco = notasDoUsuarioNoBanco[x]['nome'];
                                        // console.log('Posicao ' + x + ' nota ' + notaParaComparar);

                                        for (var xy = 0; xy < 15; xy++) {

                                            if (xy == 12 || xy == 14) { continue; }
                                            // if (materiaDoBanco != materiaParaComparar) { continue; }

                                            var notaParaComparar_banco = notasDoUsuarioNoBanco[x]['notas'][xy];
                                            var notaParaComparar_tia = notaParaComparar[xy];
                                            // console.log('Debug full notas BANCO: ' + notaParaComparar_banco);
                                            if (!notaParaComparar_banco && notaParaComparar_tia) {
                                                console.log('NOTA NOVA: ' + notaParaComparar_tia + ' TIA: ' + tiaParaComparar);
                                                var pushChannel = 't' + tiaParaComparar;

                                                var textShowNota = 'Nova nota ' + nomeDasNotas[xy] + ' em ' + materiaParaComparar + ': ' + notaParaComparar_tia;
                                                var textDontShowNota = 'Nova nota ' + nomeDasNotas[xy] + ' em ' + materiaParaComparar + '.';

                                                send_push_nota(pushChannel, shouldShowNota, textShowNota, textDontShowNota);
                                                //
                                                //  Se a opcao SHOULD SEND PUSH ONCE estiver ativa, SALVA AS NOTAS NO BANCO
                                                //
                                                if (shouldSendPushOnce) {
                                                    hasNovaNota = true;
                                                    posicaoUsuarioDoBanco = y;
                                                };
                                            }

                                            //
                                            //  Essa parte é para mandar push de nota alterada. Por motivos desconhecidos, começou a dar pau no 1sem de 2016, usuarios ficavam recebendo spam
                                            //  de notas incorretas, notas que nao haviam sido alteradas e ate mesmo notas de outros usuarios. Por ser uma feature que requer um certo acompanhamento,
                                            //  ela foi desativada temporariamente!
                                            //

                                            // else if ((notaParaComparar_banco != notaParaComparar_tia) &&
                                            //     (notaParaComparar_banco != 'X' && notaParaComparar_banco != '')) {

                                            //     console.log('NOTA ALTERADA: ' + notaParaComparar_banco + notaParaComparar_tia + ' TIA: ' + tiaParaComparar);
                                            //     var pushChannel = 't' + tiaParaComparar;

                                            //     var textShowNota = 'Nota ' + nomeDasNotas[xy] + ' em ' + materiaParaComparar + ' alterada de ' + notaParaComparar_banco + ' para ' + notaParaComparar_tia;

                                            //     send_push_nota(pushChannel, shouldShowNota, textShowNota, textShowNota);

                                            //     if (shouldSendPushOnce) {
                                            //         hasNovaNota = true;
                                            //         posicaoUsuarioDoBanco = y;
                                            //     };
                                            // };
                                        };
                                    };
                                }
                            }
                            if (hasNovaNota) {
                                // console.log('Salvando Notas do User: ' + tiaParaComparar);
                                usuariosDoBanco[posicaoUsuarioDoBanco].set('notaJson', JSON.stringify(jsonUsuario)); //asda
                                usuariosDoBanco[posicaoUsuarioDoBanco].save(null, {
                                    success: function(object) {
                                        console.log("Salvo");
                                    },
                                    error: function(object, error) {
                                        console.log('Failed to save User: ' + usuariosDoBanco[posicaoUsuarioDoBanco].get('user').get('username') + ' with message: ' + error.message);
                                        response.error('Failed to save User: ' + usuariosDoBanco[posicaoUsuarioDoBanco].get('user').get('username') + ' with message: ' + error.message);
                                    }
                                });
                            }
                        }
                    },
                    error: function(httpResponse) {
                        console.error('Request failed with response code ' + httpResponse.status);
                    }
                });
            }
        },
        error: function(object, error) {
            console.log('Failed to save User: ' + userObject.username + ' with message: ' + error.message);
        }
    });
});
/*
Parse.Cloud.job("pushNota_v2", function(request, status) {

   Parse.Cloud.useMasterKey();
   var Notas = Parse.Object.extend("Notas");
   var query = new Parse.Query(Notas);
   var nomeDasNotas = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "SUB", "PARTC.", "MI", "PF", "MF"];

   query.include("user");
   query.find({
      success: function(parseUsers) {
         var usersDictionary = {};
         var tiaArray = [];
         var passArray = [];
         var unidadeArray = [];
         var usuarios = usuariosFromArray(parseUsers);
         var usuarios_por_request = 4;

         usuarios.forEach(function(usuario) {
            tiaArray.push(usuario.TIA);
            passArray.push(usuario.password);
            unidadeArray.push(usuario.unidade);
         });

         for (var i = 0; i < tiaArray.length; i += usuarios_por_request) {

            var jsonTiaTotal = JSON.stringify(tiaArray.slice(i, i + usuarios_por_request));
            var jsonPassTotal = JSON.stringify(passArray.slice(i, i + usuarios_por_request));
            var jsonUnidadeTotal = JSON.stringify(unidadeArray.slice(i, i + usuarios_por_request));
            console.log('Letra i: ' + i + ' JsonTiaTotalSizeSclied: ' + jsonTiaTotal);

            Parse.Cloud.httpRequest({
               method: 'POST',
               url: 'http://tia-pushwebservice.herokuapp.com/tiaPushJob.php',
               body: {
                  userTia: jsonTiaTotal,
                  userPass: jsonPassTotal,
                  userUnidade: jsonUnidadeTotal
               },
               success: function(JSON_RESPONSE) {
                  var materias = materiasFromArray(JSON.parse(JSON_RESPONSE.text));

                  for (var i = usuarios.length - 1; i >= 0; i--) {
                     materias.forEach(function(materia) {
                        if (materia.TIA == usuarios[i].TIA) {
                           usuarios[i].materias = materia;
                        }
                     });
                  };

                  usuarios.forEach(function(usuario) {
                     var newMaterias = usuario.newMaterias;
                     var oldMaterias = usuario.oldMaterias;
                     var hasNovaNota = false;

                     newMaterias.forEach(function(newMateria) {

                        if (!newMateria.isValid) {
                           continue;
                        }

                        oldMaterias.forEach(function(oldMateria) {

                           if (newMateria.nome != oldMateria.nome) {
                              continue;
                           }

                           for (var i = newMateria.notas.length - 1, j = 0; i >= 0; i--, j++) {

                              if (i == 12 || i == 14) {
                                 continue;
                              }

                              if (!newMateria.notas[i] && oldMateria.notas[i]) {
                                 console.log('NOTA NOVA: ' + newMateria.notas[i] + ' TIA: ' + usuario.TIA);
                                 var pushChannel = 't' + usuario.TIA;
                                 var textShowNota = 'Nova nota ' + nomeDasNotas[j] + ' em ' + newMateria.nome + ': ' + newMateria.notas[i];
                                 var textDontShowNota = 'Nova nota ' + nomeDasNotas[j] + ' em ' + newMateria.nome;

                                 send_push_nota(pushChannel, shouldShowNota, textShowNota, textDontShowNota);

                                 //
                                 //  Se a opcao SHOULD SEND PUSH ONCE estiver ativa, SALVA AS NOTAS NO BANCO
                                 //
                                 if (usuario.shouldSendPushOnce) {
                                    hasNovaNota = true;
                                    posicaoUsuarioDoBanco = y;
                                 }
                                 else if ((newMateria.notas[i] != oldMateria.notas[i]) &&
                                          (newMateria.notas[i] != 'X' && newMateria.notas[i] != '')) {

                                    console.log('NOTA ALTERADA: ' + newMateria.notas[i] + oldMateria.notas[i] + ' TIA: ' + usuario.TIA);
                                    var pushChannel = 't' + usuario.TIA;

                                    var textShowNota = 'Nota ' + nomeDasNotas[j] + ' em ' + newMateria.nome + ' alterada de ' + oldMateria.notas[i] + ' para ' + newMateria.notas[i];

                                    send_push_nota(pushChannel, shouldShowNota, textShowNota, textShowNota);

                                    //
                                    //  Se a opcao SHOULD SEND PUSH ONCE estiver ativa, SALVA AS NOTAS NO BANCO
                                    //
                                    if (usuario.shouldSendPushOnce) {
                                       hasNovaNota = true;
                                       posicaoUsuarioDoBanco = y;
                                    }
                                 }
                              }
                           }
                        });
                     });
                  });
               };
              });
         }
      },
      error: function(object, error) {
         console.log('Failed to save User: ' + userObject.username + ' with message: ' + error.message);
      }
   });
});

function Materia(JSON) {

  this.nome = 'nome' in JSON ? JSON['nome'] : undefined;
  this.notas = 'notas' in JSON ? JSON['notas'] : undefined;
  this.TIA = 'tia' in JSON ? JSON['tia'] : -1;

  this.isValid = function() {
    return (this.nome != undefined &&
            this.notas != undefined &&
            this.notas.length == 15 &&
            this.TIA != -1);
  };
}

function Usuario(materias, parseUser) {

  this.TIA = parseUser.get('user').get('username');
  this.password = decrypt(parseUser.get('user').get('passwordEnc'));
  this.unidade = parseUser.get('user').get('unidade') ? parseUser.get('user').get('unidade') : "001";
  this.newMaterias = materias ? materias : undefined;
  this.oldMaterias = materiasFromArray(JSON.parse(parseUser.get('notaJson')));
  this.shouldShowNota = parseUser.get('user').get('showNota');
  this.shouldSendPushOnce = parseUser.get('user').get('pushOnlyOnce');
}

function usuariosFromArray(parseUsuarios) {

  var usuarios = [];

  parseUsuarios.forEach(function(parseUser) {
    usuarios.push(new Usuario(undefined, parseUser));
  });

  return usuarios;
}

function materiasFromArray(JSONMaterias) {
  var materias = [];

  JSONMaterias.forEach(function(materia)) {
    materias.push(new Materia(materia));
  };

  return materias;
}
*/

function is_object(obj) {
  return !(typeof obj !== 'object' && (typeof obj !== 'function' || obj === null));
}

function send_push_nota(channel, shouldShowNota, textShowNota, textDontShowNota) {
  send_push_to_channel(channel, shouldShowNota ? textShowNota : textDontShowNota);
}

function send_push_to_channel(channel, alertText) {
  send_push_to_channels([channel], alertText);
}

function send_push_to_channels(channels, alertText) {

  var pushEnabled = true;

  if (!pushEnabled) {
    console.log('Simulando push nos channels: ' + channels + ' text: ' + alertText);
  }

  else {
    Parse.Push.send({
      channels: channels,
      data: {
          alert: alertText,
          sound: 'default'
      }
    }, {
      success: function() {
          console.log('push enviado');
      },
      error: function(error) {
          console.log('push error: ' + error);
      }
    });
  }
}

function send_push_to_channel_scheduled(channel, alertText, date) {

  var pushEnabled = true;

  if (!pushEnabled) {
    console.log('Simulando push nos channels: ' + channel + ' text: ' + alertText + ' para: ' + date.toUTCString());
  }

  else {
    Parse.Push.send({
      channels: [channel],
      push_time: date,
      data: {
          alert: alertText,
          sound: 'default'
      }
    }, {
      success: function() {
          console.log('push agendado!');
      },
      error: function(error) {
          console.log('push error: ' + error);
      }
    });
  }
}



//
//  @Recebe um JSON com as notas
//  @Devolve o JSON com os X nas notas
//

function removeNotasFromJSON(userJSONResponse) {
  var arrayMaterias = userJSONResponse;
  console.log('Array size: ' + arrayMaterias.length);

  for (var i = 0; i < arrayMaterias.length; i++) {
    var arrayNotas = arrayMaterias[i]['notas'];
    // console.log('Array Antes: ' + arrayNotas);
    for (var j = 0; j < arrayNotas.length; j++) {

      if (arrayNotas[j] != '') {
        arrayNotas[j] = 'X';
      }
    };
    // console.log('Array Depois: ' + arrayNotas);
  };
  return JSON.stringify(arrayMaterias);
}

//
// - Dar push aos usuários registrados depois de Maio/2016
// - Enviar um push depois de 10m avisando ao usuário que ele ganhou push
//
Parse.Cloud.beforeSave(Parse.User, function(request, response) {
  
  Parse.Cloud.useMasterKey();
  var user_created = request.object.get("createdAt");
  var has_push = request.object.get("hasPush");
  var created_date = new Date(user_created);

  // console.log("BeforeSaving debug: " + request.object.get("username"));

  if (!has_push
    && created_date.getMonth() > 3 
    && created_date.getFullYear() >= 2016) {
    request.object.set("hasPush", true);

    var user_tia = request.object.get("username");
    var push_date = new Date();
    push_date.setMinutes(push_date.getMinutes() + 10);

    send_push_to_channel_scheduled(("t" + user_tia), "A partir de agora você receberá notificações de novas notas =)", push_date);
    console.log("Dando Push ao usuario " + user_tia);
  }

  response.success();
});

//
// Trigger - Ativada Após algum usuário enviar um feedback
// Um email é disparado usando o Mandrill
// Mandrill nao é mais Free, agora é enviado um push para o Caio e Giovanni
//

Parse.Cloud.afterSave("Feedback", function(request) {

  var Mandrill = require('mandrill');
  Mandrill.initialize('key');

  var nomeCompleto = request.object.get('nomeCompleto');
  var email        = request.object.get('email');
  var mensagem     = request.object.get('mensagem');
  var plataforma   = request.object.get('plataforma');
  var appVersion   = request.object.get('appVersion');
  var osVersion    = request.object.get('osVersion');
  var modeloCelular= request.object.get('modeloCelular');
  var tipo         = request.object.get('tipo');
  var tipoString;
  var userTia      = request.object.get('TIA');

  // if (tipo == 0) {
  //   tipoString = 'Bug report';
  // }
  // else if (tipo == 1) {
  //   tipoString = 'Sugestão';
  // }
  // else if (tipo == 2) {
  //   tipoString = 'Outros';
  // }

  // var msgFormatada = '<b>Nome do usuário: </b>' + nomeCompleto
  //                     + '<br><b>TIA:</b> ' +  userTia
  //                     + '<br><b>Email:</b> ' +  email
  //                     + '<br><b>Tipo report: </b>' + tipoString
  //                     + '<br><b>Plataforma: </b>' + plataforma
  //                     + '<br><b>Versão do app: </b>' + appVersion
  //                     + '<br><b>Versão do OS: </b>' + osVersion
  //                     + '<br><b>Modelo Celular: </b>' + modeloCelular
  //                     +'<br><br><b>Mensagem: </b>' + mensagem;
  // var subjectFormatado = '[' + plataforma + '] MackNotas Feedback';
  
  var msg = "Novo feedback do " + plataforma + " enviado por " + nomeCompleto;
  send_push_to_channels(["t31338526", "t31348408"], msg);

  // console.log('Email a ser enviado: ' + msgFormatada);

  // Mandrill não possui mais versao free!
  // 
  // Mandrill.sendEmail({
  // message: {
  //   html: msgFormatada,
  //   subject: subjectFormatado,
  //   from_email: "no-reply@macknotas.com.br",
  //   from_name: "MackNotas Feedback",
  //   to: [
  //     {
  //       email: "",
  //       name: "Giovanni"
  //     },
  //     {
  //       email: "",
  //       name: "Caio"
  //     }
  //   ]
  // },
  // async: true
  // },{
  //   success: function(httpResponse) {
  //     console.log(httpResponse);
  //     response.success("Email sent!");
  //   },
  //   error: function(httpResponse) {
  //     console.error(httpResponse);
  //     response.error("Uh oh, something went wrong");
  //   }
  // });
});

//
//
//

Parse.Cloud.define("inviteUserToPush", function(request, response) {

  Parse.Cloud.useMasterKey();

  var user = request.user;
  var Invite = Parse.Object.extend("Invite");
  var query = new Parse.Query(Invite);

  query.equalTo('user', user);
  query.first({
  success: function(object) {

    var invite = object;
    var numberOfInvitesAvailable = invite.get("invitesDisponiveis");
    var invitedUsers = invite.get("usersInvited");

    if (numberOfInvitesAvailable == 0) {
      response.error('Você não possui mais convites!');
    }

    var userQuery = new Parse.Query(Parse.User);

    userQuery.equalTo("username", request.params.tia);
    userQuery.first({
      success: function(invitedUser) {
        if (!invitedUser) {
          response.error('Usuário não registrado no MackNotas!');
        }

        else if (invitedUser.get("hasPush") == true) {
          response.error('Usuário já possui notificação de notas ativo!');
        }

        else {
          invite.set("invitesDisponiveis", --numberOfInvitesAvailable);
          invitedUsers.push(request.params.tia);

          invitedUser.set("hasPush", true);
          invitedUser.save(null, {
            success: function(inviteSaved) {
            invite.save(null, {
                success: function(inviteSaved) {
                  var InviteClass = Parse.Object.extend("Invite");
                  var newInviteUser = new InviteClass();
                  newInviteUser.set("user", invitedUser);
                  newInviteUser.set("invitesDisponiveis", 0);
                  newInviteUser.set("usersInvited", []);
                  newInviteUser.save(null, {

                    success: function(newInviteUser) {
                      response.success(inviteSaved);
                  },
                    error: function(gameScore, error) {
                    response.error(error.code + ": " + error.message);
                  }
                });
                },
                error: function(gameScore, error) {
                  response.error(error.code + ": " + error.message);
                }
              });
            },
            error: function(gameScore, error) {
              response.error(error.code + ": " + error.message);
            }
          });
        }
      },
      error: function(error) {
        response.error(error.code + ": " + error.message);
      }
    });
  },

  error: function(error) {
      response.error(error.code + ": " + error.message);
    }
  });

});

Parse.Cloud.define("CampaignUserHashPush", function(request, response) {

    Parse.Cloud.useMasterKey();
    var query = new Parse.Query(Parse.User);

    query.equalTo("hasPush", true);
    query.limit(1000);
    query.find({
      success: function(users) {
        var usersChannels = new Array();
        
        users.forEach(function(user) {
          usersChannels.push('t' + user.get("username"));
        })
        console.log('Quantidade de push: ' + usersChannels.length);
        send_push_to_channels(usersChannels, "A partir de agora você recebera notificações de novas notas =)")
      },
      error: function(error) {
        console.log('Failed to CampaignUserHashPush, with error code: ' + error.message);
      }
    });
});

Parse.Cloud.define("logoutUserIfNeeded", function(request, response) {

    var userTia = request.params.userTia;

    if (!userTia) {
        response.success(false);
        return;
    }

    Parse.Cloud.useMasterKey();
    var query = new Parse.Query(Parse.User);

    query.equalTo("username", request.params.userTia);

    query.first({
        success: function(user) {

            if (user.get('shouldLogout')) {
                user.set('shouldLogout', false);
                user.save(null, {
                    success: function(user) {
                        console.log('Deslogar usuario' + user.get('username'));
                        response.success(1);
                    },
                    error: function(user, error) {
                        console.log('Failed to save shouldLogout, with error code: ' + error.message);
                    }
                });
            } else {
                response.success(0);
            }
        },
        error: function(error) {
            alert("Error: " + error.code + " " + error.message);
        }
    });
});

Parse.Cloud.define("forceAllUsersLogoutQuery", function(request, status) {

  Parse.Cloud.useMasterKey();
  var query = new Parse.Query(Parse.User);
  query.limit(1000);
  query.find().then(function(results) {
    for (var i = results.length - 1; i >= 0; i--) {
      var user = results[i];
      user.set('shouldLogout', true);
      console.log("setting TRUE: " + user.get('username'));
    };
    Parse.Object.saveAll(results, {
      success: function(list) {
        console.log("Salvo: " + list);
      },
      error: function(error) {
      },
    });
  });
});

//===============================================================================================================================
//===============================================================================================================================
//=================================================== DAQUI PRA CIMA ============================================================
//===============================================================================================================================
//===============================================================================================================================

//
//  ZONA DE TESTES, DIVIRTA-SE
//


Parse.Cloud.define("performQuery", function(request, status) {

  var push_date = new Date();
  push_date.setMinutes(push_date.getMinutes() + 1); 

  send_push_to_channel_scheduled("t31338526", "Teste123", push_date);
  // Parse.Cloud.useMasterKey();
  // var query = new Parse.Query(Parse.User);
  
  // query.first({
  //   success: function(object) {
  //     console.log(object);
  //     console.log(object["createdAt"]);
  //     var date = new Date(object["createdAt"]);
  //     console.log(date.getMonth());
  //   },
  //   error: function(error) {

  //   }
  // });
});

Parse.Cloud.define("testeQuery", function(request, status) {


   Parse.Cloud.httpRequest({
    method: 'POST',
    url: 'http://tia-pushwebservice.herokuapp.com/tiaPushJob.php',
    body: {
      userTia: JSON.stringify(['31338526']),
      userPass: JSON.stringify(['']),
      userUnidade: JSON.stringify(['001'])
    },
    success: function(httpResponse) {
      var Notas = Parse.Object.extend("Notas");
      var query = new Parse.Query(Notas);
      query.equalTo("objectId", "BqwtK0sNiW");
      query.include("user");
      query.find({

        success: function(results) {
          var userObject = results[0];

          userObject.set('notaJson', removeNotasFromJSON(httpResponse.text));
          userObject.save(null, {
            success: function(object) {
              console.log("true");
            },
            error: function(object, error) {
              console.log('Failed to save User: ' + userObject.username + ' with message: ' + error.message);
              response.error('Failed to save User: ' + userObject.username + ' with message: ' + error.message);
            }
          });

          console.log("TIA " + results[0].get('user').get('username'));

        },
        error: function(error) {
          alert("Error: " + error.code + " " + error.message);
        }
      });
    },

    error: function(httpResponse) {
      console.error('Request failed with response code ' + httpResponse.status);
    }
  });
});
