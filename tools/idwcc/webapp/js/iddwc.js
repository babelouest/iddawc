var currentSession = {};

var responseTypes = {
  none:               0x00000000,
  code:               0x00000001,
  token:              0x00000010,
  id_token:           0x00000100,
  password:           0x00001000,
  client_credentials: 0x00010000,
  refresh_token:      0x00100000,
  device_code:        0x01000000
};

const authMethodGet              = 0x00000001;
const authMethodPost             = 0x00000010;
const authMethodJwtSignSecret    = 0x00000100;
const authMethodJwtSignPrivkey   = 0x00001000;
const authMethodJwtEncryptSecret = 0x00010000;
const authMethodJwtEncryptPubkey = 0x00100000;

var tokenMethodNone              = 0x00000000;
var tokenMethodSecretBasic       = 0x00000001;
var tokenMethodSecretPost        = 0x00000010;
var tokenMethodTlsCertificate    = 0x00000100;
var tokenMethodJwtSignSecret     = 0x00001000;
var tokenMethodJwtSignPrivkey    = 0x00010000;
var tokenMethodJwtEncryptSecret  = 0x00100000;
var tokenMethodJwtEncryptPubkey  = 0x01000000;

var remoteVerifyNone          = 0x0000;
var remoteHostVerifyPeer      = 0x0001;
var remoteHostVerifyHostname  = 0x0010;
var remoteProxyVerifyPeer     = 0x0100;
var remoteProxyVerifyHostname = 0x1000;

$( document ).ready(function() {

  $("#saveSession").click(() => {
    saveSession()
    .then(() => {
      getSession();
    });
  });

  $("#exportSession").click(() => {
    var pom = document.createElement('a');
    pom.setAttribute('href', "data:application/json," + encodeURIComponent(JSON.stringify(currentSession)));
    pom.setAttribute('download', "iddwc.json");

    if (document.createEvent) {
      var event = document.createEvent('MouseEvents');
      event.initEvent('click', true, true);
      pom.dispatchEvent(event);
    }
    else {
      pom.click();
    }
  });

  $("#importSession").click((evt) => {
    evt.preventDefault();
    $('#importFile').trigger('click');
  });

  $("#cleanSession").click((evt) => {
    $.ajax({
      method: "POST",
      url: "/api/session",
      data: JSON.stringify({}),
      contentType: "application/json; charset=utf-8"
    })
    .then(() => {
      getSession();
    })
    .fail((error) => {
      showModal("Error saving session: "+error.responseText);
    });
  });

  $("#client_secret-toggle").click(() => {
    if ($("#client_secret").prop("type") === "password") {
      $("#client_secret").prop("type", "text");
    } else {
      $("#client_secret").prop("type", "password");
    }
  });

  $("#scopeSupported").change(() => {
    if ($("#scopeSupported").val()) {
      $("#scope").val(($("#scope").val()+" "+$("#scopeSupported").val()).trim());
    }
  });

  $("#openid_config_endpoint-download").click(() => {
    if ($("#openid_config_endpoint").val()) {
      saveSession()
      .then(() => {
        return $.ajax({
          method: "POST",
          url: "/api/configDownload",
          contentType: "application/json; charset=utf-8"
        });
      })
      .then(() => {
        showModal("Success");
        getSession();
      })
      .fail((error) => {
        if (error.status == 400) {
          showModal("Error getting config: "+error.responseText);
        } else {
          showModal("Error getting config");
        }
      });
    }
  });

  $("#userinfo-download").click(() => {
    if ($("#access_token").val()) {
      saveSession()
      .then(() => {
        return $.ajax({
          method: "POST",
          url: "/api/userinfoDownload",
          contentType: "application/json; charset=utf-8"
        });
      })
      .then(() => {
        showModal("Success");
        getSession();
      })
      .fail((error) => {
        if (error.status === 400) {
          showModal("Error running userinfo: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
        } else if (error.status === 403) {
          showModal("Error running userinfo: unauthorized<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
        } else {
          showModal("Error running userinfo: server error");
        }
      });
    }
  });

  $("#introspection-btn").click(() => {
    currentSession.token_target_type_hint = $("#introspectionType").val();
    if (currentSession.token_target_type_hint === "access_token") {
      currentSession.token_target = $("#access_token").val();
    } else if (currentSession.token_target_type_hint === "refresh_token") {
      currentSession.token_target = $("#refresh_token").val();
    } else if (currentSession.token_target_type_hint === "id_token") {
      currentSession.token_target = $("#id_token").val();
    }
    saveSession()
    .then(() => {
      return $.ajax({
        method: "POST",
        url: "/api/introspectDownload",
        data: {
                authentication: $("#introspectionAuthType").val(),
                access_token: $("#introspectionAccessToken").val()
              }
      });
    })
    .then((res) => {
      showModal("Success");
      $("#introspection_payload").empty().html(JSON.stringify(res, null, 2));
    })
    .fail((error) => {
      if (error.status === 400) {
        showModal("Error running introspection: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else if (error.status === 403) {
        showModal("Error running introspection: unauthorized<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else {
        showModal("Error running introspection: server error");
      }
    });
  });

  $("#revocation-btn").click(() => {
    currentSession.token_target_type_hint = $("#introspectionType").val();
    if (currentSession.token_target_type_hint === "access_token") {
      currentSession.token_target = $("#access_token").val();
    } else if (currentSession.token_target_type_hint === "refresh_token") {
      currentSession.token_target = $("#refresh_token").val();
    } else if (currentSession.token_target_type_hint === "id_token") {
      currentSession.token_target = $("#id_token").val();
    }
    saveSession()
    .then(() => {
      return $.ajax({
        method: "PUT",
        url: "/api/revoke",
        data: {
                authentication: $("#introspectionAuthType").val(),
                access_token: $("#introspectionAccessToken").val()
              }
      });
    })
    .then((res) => {
      showModal("Success");
      $("#introspection_payload").empty().html(JSON.stringify(res, null, 2));
    })
    .fail((error) => {
      if (error.status === 400) {
        showModal("Error running revocation: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else if (error.status === 403) {
        showModal("Error running revocation: unauthorized<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else {
        showModal("Error running revocation: server error");
      }
    })
  });

  $("#nonceGenerate").click(() => {
    saveSession()
    .then(() => {
      return $.ajax({
        method: "PUT",
        url: "/api/generate",
        data: {property: "nonce"}
      });
    })
    .then(() => {
      getSession();
    });
  });

  $("#PKCEGenerate").click(() => {
    saveSession()
    .then(() => {
      return $.ajax({
        method: "PUT",
        url: "/api/generate",
        data: {property: "pkce"}
      });
    })
    .then(() => {
      getSession();
    });
  });

  $("#stateGenerate").click(() => {
    saveSession()
    .then(() => {
      return $.ajax({
        method: "PUT",
        url: "/api/generate",
        data: {property: "state"}
      });
    })
    .then(() => {
      getSession();
    });
  });

  $("#jtiGenerate").click(() => {
    saveSession()
    .then(() => {
      return $.ajax({
        method: "PUT",
        url: "/api/generate",
        data: {property: "jti"}
      });
    })
    .then(() => {
      getSession();
    });
  });

  $("#runAuthBtn").click(() => {
    if ($("#authorization_endpoint").val() && $("#client_id").val()) {
      saveSession()
      .then(() => {
        return $.ajax({
          method: "PUT",
          url: "/api/auth",
          data: {
            use_par: $("#use_par").prop("checked")
          }
        });
      })
      .then((res) => {
        document.location.href = res.url;
      })
      .fail((error) => {
        if (error.status === 400) {
          showModal("Error running auth: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
        } else {
          showModal("Error running auth: server error");
        }
      });
    } else {
      showModal("Auth endpoint or client_id missing");
    }
  });

  $("#runTokenBtn").click(() => {
    if ($("#token_endpoint").val()) {
      saveSession()
      .then(() => {
        return $.ajax({
          method: "PUT",
          url: "/api/token"
        });
      })
      .then(() => {
        showModal("Success");
        getSession();
      })
      .fail((error) => {
        if (error.status === 400) {
          showModal("Error running token: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
        } else if (error.status === 403) {
          showModal("Error running token<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
        } else {
          showModal("Error running token: server error");
        }
      });
    }
  });

  $("#runDeviceBtn").click(() => {
    if ($("#device_authorization_endpoint").val()) {
      saveSession()
      .then(() => {
        return $.ajax({
          method: "PUT",
          url: "/api/device"
        });
      })
      .then(() => {
        showModal("Success");
        getSession();
      })
      .fail((error) => {
        if (error.status === 400) {
          showModal("Error running token: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
        } else if (error.status === 403) {
          showModal("Error running token: unauthorized<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
        } else {
          showModal("Error running token: server error");
        }
      });
    }
  });

  $("#clearTokenBtn").click(() => {
    $("#code").val("");
    $("#id_token").val("");
    $("#access_token").val("");
    $("#refresh_token").val("");
    $("#token_target").val("");
    $("#device_auth_code").val("");
    $("#device_auth_user_code").val("");
    $("#device_auth_verification_uri").val("");
    $("#device_auth_verification_uri_complete").val("");
    $("#register_payload").empty();
    $("#access_token_payload").empty();
    $("#userinfo_payload").empty();
    delete(currentSession.id_token_payload);
    delete(currentSession.access_token_payload);
    delete(currentSession.userinfo_payload);
    saveSession()
    .always(() => {
      loadSession();
    });
  });

  $("#addClaimsBtn").click(() => {
    $("#claimName").val("");
    $("#claimValue").val("");
    $("#claimTarget").val("All");
    $("#claimEssential").val("null");
    $("#claimModal").modal('show');
  });
  
  $("#cleanClaimsBtn").click(() => {
    currentSession.claims = {
      userinfo: {},
      id_token: {}
    };
    saveSession()
    .then(() => {
      loadSession();
    });
  });

  $("#addRarBtn").click(() => {
    $("#RARType").val("");
    $("#RARValue").val("");
    $("#RARModal").modal('show');
  });
  
  $("#cleanRarBtn").click(() => {
    currentSession.authorization_details = [];
    saveSession()
    .then(() => {
      loadSession();
    });
  });
  
  $("#claimSave").click(() => {
    var name = $("#claimName").val();
    if (name) {
      var value = false;
      if ($("#claimValue").val()) {
        try {
          value = JSON.parse($("#claimValue").val())
        } catch (e) {
          showModal("Error claim value is not in JSON format");
        }
      } else if ($("#claimEssential").val() === "null") {
        value = null;
      } else if ($("#claimEssential").val() === "true") {
        value = {essential: true};
      } else if ($("#claimEssential").val() === "false") {
        value = {essential: false};
      }
      
      if (value !== false) {
        if ($("#claimTarget").val() === "All") {
          currentSession.claims.userinfo[name] = value;
          currentSession.claims.id_token[name] = value;
        } else if ($("#claimTarget").val() === "userinfo") {
          currentSession.claims.userinfo[name] = value;
        } else if ($("#claimTarget").val() === "id_token") {
          currentSession.claims.id_token[name] = value;
        }
        saveSession()
        .then(() => {
          loadSession();
        });
      }
      $("#claimModal").modal('hide');
    }
  });
  
  $("#RARSave").click(() => {
    var type = $("#RARType").val();
    if (type) {
      var value = {};
      if ($("#RARValue").val()) {
        try {
          value = JSON.parse($("#RARValue").val());
          if (typeof value !== "object") {
            showModal("Invalid RAR value, must be an object");
            value = false;
          }
        } catch (e) {
          showModal("Invalid RAR value, must be a JSON object");
          value = false;
        }
      }
      if (value !== false) {
        value.type = type;
        currentSession.authorization_details.push(value);
        saveSession()
        .then(() => {
          loadSession();
        });
        $("#RARModal").modal('hide');
      }
    }
  });

  $("#introspectUseCurrentAT").click(() => {
    $("#introspectionAccessToken").val($("#access_token").val());
  });

  $("#registerUseCurrentAT").click(() => {
    $("#clientRegistrationAccessToken").val($("#access_token").val());
  });
  
  $("#registerClient").click(() => {
    var parameters = prepareClientRegistration();
    saveSession()
    .then(() => {
      return $.ajax({
        method: "POST",
        url: "/api/register",
        data: {
                authentication: $("#useAccessToken").prop("checked")?"access_token":undefined,
                access_token: $("#clientRegistrationAccessToken").val(),
                update: $("#registerUpdateSession").prop("checked")?"1":"0",
                parameters: JSON.stringify(parameters)
              }
      });
    })
    .then((res) => {
      showModal("Success");
      $("#register_payload").empty().html(JSON.stringify(res, null, 2));
      if (res.registration_access_token && res.registration_client_uri) {
        $("#clientRegistrationAccessToken").val(res.registration_access_token);
        $("#useAccessToken").prop("checked", true);
      }
      getSession();
    })
    .fail((error) => {
      if (error.status === 400) {
        showModal("Error running registration: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else if (error.status === 403) {
        showModal("Error running registration: unauthorized<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else {
        showModal("Error running registration: server error");
      }
    });
  });
  
  $("#manageClient").click(() => {
    var parameters = prepareClientRegistration();
    parameters.client_id = $("#client_id").val();
    saveSession()
    .then(() => {
      return $.ajax({
        method: "PUT",
        url: "/api/register",
        data: {
                access_token: $("#clientRegistrationAccessToken").val(),
                update: $("#registerUpdateSession").prop("checked")?"1":"0",
                parameters: JSON.stringify(parameters)
              }
      });
    })
    .then((res) => {
      showModal("Success");
      $("#register_payload").empty().html(JSON.stringify(res, null, 2));
      if (res.registration_access_token && res.registration_client_uri) {
        $("#clientRegistrationAccessToken").val(res.registration_access_token);
        $("#useAccessToken").prop("checked", true);
      }
      getSession();
    })
    .fail((error) => {
      if (error.status === 400) {
        showModal("Error managing registration: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else if (error.status === 403) {
        showModal("Error managing registration: unauthorized<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else {
        showModal("Error managing registration: server error");
      }
    });
  });

  $("#manageClientGet").click(() => {
    saveSession()
    .then(() => {
      return $.ajax({
        method: "GET",
        url: "/api/register?access_token="+encodeURIComponent($("#clientRegistrationAccessToken").val())
      });
    })
    .then((res) => {
      showModal("Success");
      $("#register_payload").empty().html(JSON.stringify(res, null, 2));
    })
    .fail((error) => {
      if (error.status === 400) {
        showModal("Error getting registration: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else if (error.status === 403) {
        showModal("Error getting registration: unauthorized<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
      } else {
        showModal("Error getting registration: server error");
      }
    });
  });

  $("#access_token-verify").click(() => {
    if ($("#access_token").val()) {
      saveSession()
      .then(() => {
        return $.ajax({
          method: "POST",
          url: "/api/accessTokenVerify",
          contentType: "application/json; charset=utf-8"
        });
      })
      .then(() => {
        showModal("Success");
        getSession();
      })
      .fail((error) => {
        if (error.status === 400) {
          showModal("Error running verification: invalid parameters<div><b>Error:</b> <i>"+error.responseJSON.error+"</i></div><div><b>Error description:</b> <i>"+(error.responseJSON.error_description||" - ")+"</i></div>");
        } else {
          showModal("Error running verification: server error");
        }
      });
    }
  });

  $("#importFile").change(() => {
    var fr=new FileReader();
    fr.onload=function() {
      try {
        currentSession = JSON.parse(fr.result);
        loadSession();
      } catch (e) {
        showModal("Error importing session");
      }
    }

    fr.readAsText($("#importFile").prop('files')[0]);
  });

  $("#resourceHttpMethodSelect").change(() => {
    if ($("#resourceHttpMethodSelect").val()) {
      $("#resourceHttpMethod").val($("#resourceHttpMethodSelect").val());
    }
  });
  
  $("#resourceRun").click(() => {
    if ($("#resourceHttpUrl").val()) {
      saveSession()
      .then(() => {
        var headers = undefined, body = undefined, errors = false;
        if ($("#resourceHeaders").val()) {
          headers = {};
          $("#resourceHeaders").val().split("\n").forEach((header) => {
            if (header) {
              var vals = header.split(":");
              if (vals.length >= 2) {
                headers[vals[0]] = vals[1];
              } else {
                headers[vals[0]] = null;
              }
            }
          });
        }
        if ($("#resourceBody").val()) {
          if ($("#resourceBodyType").val() == "JSON") {
            try {
              body = JSON.parse($("#resourceBody").val());
            } catch (e) {
              showModal("Error body value is not in JSON format");
              errors = true;
            }
          } else {
            body = {};
            $("#resourceBody").val().split("\n").forEach((param) => {
              if (param) {
                var vals = param.split(":");
                if (vals.length >= 2) {
                  body[vals[0]] = vals[1];
                } else {
                  body[vals[0]] = null;
                }
              }
            });
          }
        }
        if (!errors) {
          var request = {
            method: $("#resourceHttpMethod").val()||"GET",
            url: $("#resourceHttpUrl").val(),
            headers: headers,
            bodyType: $("#resourceBodyType").val(),
            body: body
          };
          $.ajax({
            method: "POST",
            url: "/api/resourceRequest",
            data: JSON.stringify(request),
            contentType: "application/json; charset=utf-8"
          })
          .then((res) => {
            if (res.bodyType === "JSON") {
              $("#resource_results").empty().html(JSON.stringify(res, null, 2));
            } else {
              $("#resource_results").empty().html(JSON.stringify(res, null, 2).replaceAll("\\n", "\n"));
            }
          })
          .fail((error) => {
            showModal("Error saving session: "+error.responseText);
          });
        }
      });
    }
  });
  
  $("#resourceClean").click(() => {
    $("#resource_results").empty();
  });

  function getSession() {
    $.get("/api/session")
    .then((res) => {
      currentSession = res;
      loadSession();
    })
    .fail((error) => {
      showModal("Error loading session: "+error.responseText);
    });
  }

  function loadSession() {
    $("#client_id").val(currentSession.client_id)||"";
    $("#client_secret").val(currentSession.client_secret||"");
    $("#redirect_uri").val(currentSession.redirect_uri||"");
    $("#openid_config_endpoint").val(currentSession.openid_config_endpoint||"");
    $("#authorization_endpoint").val(currentSession.authorization_endpoint||"");
    $("#token_endpoint").val(currentSession.token_endpoint||"");
    $("#userinfo_endpoint").val(currentSession.userinfo_endpoint||"");
    $("#revocation_endpoint").val(currentSession.revocation_endpoint||"");
    $("#introspection_endpoint").val(currentSession.introspection_endpoint||"");
    $("#registration_endpoint").val(currentSession.registration_endpoint||"");
    $("#device_authorization_endpoint").val(currentSession.device_authorization_endpoint||"");
    $("#pushed_authorization_request_endpoint").val(currentSession.pushed_authorization_request_endpoint||"");
    $("#server_jwks").val(JSON.stringify(currentSession.server_jwks, null, 2)||"");
    $("#server-kid").val(currentSession["server-kid"]||"");
    $("#openid_config_strict").prop("checked", !!(currentSession.openid_config_strict));
    $("#code").val(currentSession.code||"");
    $("#scope").val(currentSession.scope||"");
    $("#nonce").val(currentSession.nonce||"");
    $("#state").val(currentSession.state||"");
    $("#token_jti").val(currentSession.token_jti||"");
    $("#id_token").val(currentSession.id_token||"");
    $("#access_token").val(currentSession.access_token||"");
    $("#refresh_token").val(currentSession.refresh_token||"");
    $("#id_token_payload").empty().html(JSON.stringify(currentSession.id_token_payload, null, 2));
    $("#client_jwks").val(JSON.stringify(currentSession.client_jwks, null, 2)||"");
    $("#client-kid").val(currentSession["client-kid"]||"");
    $("#sig-alg").val(currentSession["sig-alg"]||"None");
    $("#enc-alg").val(currentSession["enc-alg"]||"None");
    $("#enc").val(currentSession.enc||"None");
    $("#dpop_kid").val(currentSession.dpop_kid||"");
    $("#dpop-sig-alg").val(currentSession["dpop-sig-alg"]||"None");
    $("#remote_cert_flag-host-peer").prop("checked", !!(currentSession.remote_cert_flag&remoteHostVerifyPeer));
    $("#remote_cert_flag-host-name").prop("checked", !!(currentSession.remote_cert_flag&remoteHostVerifyHostname));
    $("#remote_cert_flag-proxy-peer").prop("checked", !!(currentSession.remote_cert_flag&remoteProxyVerifyPeer));
    $("#remote_cert_flag-proxy-name").prop("checked", !!(currentSession.remote_cert_flag&remoteProxyVerifyHostname));
    $("#use_dpop").prop("checked", !!(currentSession.use_dpop));
    $("#decrypt_code").prop("checked", !!(currentSession.decrypt_code));
    $("#decrypt_refresh_token").prop("checked", !!(currentSession.decrypt_refresh_token));
    $("#decrypt_id_token").prop("checked", !!(currentSession.decrypt_id_token));
    $("#decrypt_access_token").prop("checked", !!(currentSession.decrypt_access_token));
    $("#pkce_method").val((currentSession.pkce_method&&currentSession.pkce_method.toString())||"0");
    $("#pkce_code_verifier").val(currentSession.pkce_code_verifier||"");
    $("#device_auth_code").val(currentSession.device_auth_code||"");
    $("#device_auth_user_code").val(currentSession.device_auth_user_code||"");
    $("#device_auth_verification_uri").val(currentSession.device_auth_verification_uri||"");
    $("#device_auth_verification_uri_complete").val(currentSession.device_auth_verification_uri_complete||"");
    $("#device_auth_expires_in").val(currentSession.device_auth_expires_in||"");
    $("#device_auth_interval").val(currentSession.device_auth_interval||"");
    $("#resource_indicator").val(currentSession.resource_indicator||"");

    if (currentSession.userinfo) {
      $("#userinfo_payload").empty().html(JSON.stringify(JSON.parse(currentSession.userinfo), null, 2));
    }

    if (!$("#redirect_uri").val()) {
      $("#redirect_uri").val(location.protocol+'//'+location.hostname+(location.port ? ':'+location.port: '')+"/callback");
    }

    if (!$("#clientRegistrationRedirectUri").val()) {
      $("#clientRegistrationRedirectUri").val(location.protocol+'//'+location.hostname+(location.port ? ':'+location.port: '')+"/callback");
    }

    if (currentSession.server_jwks) {
      var jwks = [];
      currentSession.server_jwks.keys.forEach(jwk => {
        jwks.push(
          {
            kid: jwk.kid,
            kty: jwk.kty,
            alg: jwk.alg
          }
        );
      });
      $("#server_jwks_digest").empty().html(JSON.stringify(jwks, null, 2));
    }

    if (!currentSession.openid_config) {
      Object.keys(responseTypes).forEach((responseType, index) => {
        if (responseTypes[responseType] === responseTypes.code) {
          $("#response_type").append('<option value="'+responseTypes[responseType]+'" selected="true">'+ responseType +'</option>');
        } else {
          $("#response_type").append('<option value="'+responseTypes[responseType]+'">'+ responseType +'</option>');
        }
      });
    } else {
      $("#response_type").empty();
      currentSession.openid_config.response_types_supported.forEach((responseType, index) => {
        var responseTypeArray = responseType.split(" ");
        if (responseTypeArray.length > 1) {
          var typeValue = 0;
          responseTypeArray.forEach((curType) => {
            typeValue |= responseTypes[curType];
          });
          if (!index) {
            $("#response_type").append('<option value="'+typeValue+'" selected="true">'+ responseType +'</option>');
          } else {
            $("#response_type").append('<option value="'+typeValue+'">'+ responseType +'</option>');
          }
        } else {
          var typeValue = responseTypes[responseTypeArray[0]];
          if (typeValue) {
            $("#response_type").append('<option value="'+typeValue+'">'+ responseType +'</option>');
          }
        }
      });
      if (currentSession.openid_config.grant_types_supported && currentSession.openid_config.grant_types_supported.indexOf("urn:ietf:params:oauth:grant-type:device_code") > -1) {
        $("#response_type").append('<option value="'+responseTypes.device_code+'">device_code</option>');
      }
      $("#authorization_endpoint-details").empty();
      if (currentSession.openid_config.request_object_signing_alg_values_supported) {
        $("#authorization_endpoint-details").append("<b>request_object_signing_alg_values_supported</b>:\n  "+currentSession.openid_config.request_object_signing_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.request_object_encryption_alg_values_supported) {
        $("#authorization_endpoint-details").append("<b>request_object_encryption_alg_values_supported</b>:\n  "+currentSession.openid_config.request_object_encryption_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.request_object_encryption_enc_values_supported) {
        $("#authorization_endpoint-details").append("<b>request_object_encryption_enc_values_supported</b>:\n  "+currentSession.openid_config.request_object_encryption_enc_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.response_modes_supported) {
        $("#authorization_endpoint-details").append("<b>response_modes_supported</b>:\n  "+currentSession.openid_config.response_modes_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.grant_types_supported) {
        $("#authorization_endpoint-details").append("<b>grant_types_supported</b>:\n  "+currentSession.openid_config.grant_types_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.display_values_supported) {
        $("#authorization_endpoint-details").append("<b>display_values_supported</b>:\n  "+currentSession.openid_config.display_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.ui_locales_supported) {
        $("#authorization_endpoint-details").append("<b>ui_locales_supported</b>:\n  "+currentSession.openid_config.ui_locales_supported.join(", ")+"\n\n");
      }

      $("#token_endpoint-details").empty();
      if (currentSession.openid_config.token_endpoint_auth_methods_supported) {
        $("#token_endpoint-details").append("<b>token_endpoint_auth_methods_supported</b>:\n  "+currentSession.openid_config.token_endpoint_auth_methods_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.token_endpoint_auth_signing_alg_values_supported) {
        $("#token_endpoint-details").append("<b>token_endpoint_auth_signing_alg_values_supported</b>:\n  "+currentSession.openid_config.token_endpoint_auth_signing_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.request_object_encryption_alg_values_supported) {
        $("#token_endpoint-details").append("<b>request_object_encryption_alg_values_supported</b>:\n  "+currentSession.openid_config.request_object_encryption_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.request_object_encryption_enc_values_supported) {
        $("#token_endpoint-details").append("<b>request_object_encryption_enc_values_supported</b>:\n  "+currentSession.openid_config.request_object_encryption_enc_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.mtls_endpoint_aliases && currentSession.openid_config.mtls_endpoint_aliases.token_endpoint) {
        $("#token_endpoint-details").append("<b>mtls token_endpoint</b>:\n  "+currentSession.openid_config.mtls_endpoint_aliases.token_endpoint+"\n\n");
      }

      $("#userinfo_endpoint-details").empty();
      if (currentSession.openid_config.userinfo_signing_alg_values_supported) {
        $("#userinfo_endpoint-details").append("<b>userinfo_signing_alg_values_supported</b>:\n  "+currentSession.openid_config.userinfo_signing_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.userinfo_encryption_alg_values_supported) {
        $("#userinfo_endpoint-details").append("<b>userinfo_encryption_alg_values_supported</b>:\n  "+currentSession.openid_config.userinfo_encryption_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.userinfo_encryption_enc_values_supported) {
        $("#userinfo_endpoint-details").append("<b>userinfo_encryption_enc_values_supported</b>:\n  "+currentSession.openid_config.userinfo_encryption_enc_values_supported.join(", ")+"\n\n");
      }

      $("#revocation_endpoint-details").empty();
      if (currentSession.openid_config.revocation_endpoint_auth_methods_supported) {
        $("#revocation_endpoint-details").append("<b>revocation_endpoint_auth_methods_supported</b>:\n  "+currentSession.openid_config.revocation_endpoint_auth_methods_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.revocation_signing_alg_values_supported) {
        $("#revocation_endpoint-details").append("<b>revocation_signing_alg_values_supported</b>:\n  "+currentSession.openid_config.revocation_signing_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.revocation_encryption_alg_values_supported) {
        $("#revocation_endpoint-details").append("<b>revocation_encryption_alg_values_supported</b>:\n  "+currentSession.openid_config.revocation_encryption_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.revocation_encryption_enc_values_supported) {
        $("#revocation_endpoint-details").append("<b>revocation_encryption_enc_values_supported</b>:\n  "+currentSession.openid_config.revocation_encryption_enc_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.mtls_endpoint_aliases && currentSession.openid_config.mtls_endpoint_aliases.revocation_endpoint) {
        $("#revocation_endpoint-details").append("<b>mtls revocation_endpoint</b>:\n  "+currentSession.openid_config.mtls_endpoint_aliases.revocation_endpoint+"\n\n");
      }

      $("#introspection_endpoint-details").empty();
      if (currentSession.openid_config.introspection_endpoint_auth_methods_supported) {
        $("#introspection_endpoint-details").append("<b>introspection_endpoint_auth_methods_supported</b>:\n  "+currentSession.openid_config.introspection_endpoint_auth_methods_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.introspection_signing_alg_values_supported) {
        $("#introspection_endpoint-details").append("<b>introspection_signing_alg_values_supported</b>:\n  "+currentSession.openid_config.introspection_signing_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.introspection_encryption_alg_values_supported) {
        $("#introspection_endpoint-details").append("<b>introspection_encryption_alg_values_supported</b>:\n  "+currentSession.openid_config.introspection_encryption_alg_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.introspection_encryption_enc_values_supported) {
        $("#introspection_endpoint-details").append("<b>introspection_encryption_enc_values_supported</b>:\n  "+currentSession.openid_config.introspection_encryption_enc_values_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.mtls_endpoint_aliases && currentSession.openid_config.mtls_endpoint_aliases.introspection_endpoint) {
        $("#introspection_endpoint-details").append("<b>mtls introspection_endpoint</b>:\n  "+currentSession.openid_config.mtls_endpoint_aliases.introspection_endpoint+"\n\n");
      }

      $("#device_authorization_endpoint-details").empty();
      if (currentSession.openid_config.mtls_endpoint_aliases && currentSession.openid_config.mtls_endpoint_aliases.device_authorization_endpoint) {
        $("#device_authorization_endpoint-details").append("<b>mtls device_authorization_endpoint</b>:\n  "+currentSession.openid_config.mtls_endpoint_aliases.device_authorization_endpoint+"\n\n");
      }

      $("#pushed_authorization_request_endpoint-details").empty();
      $("#pushed_authorization_request_endpoint-details").append("<b>require_pushed_authorization_requests</b>: "+currentSession.openid_config.require_pushed_authorization_requests||"false");

      $("#server_config").empty();
      Object.keys(currentSession.openid_config).forEach((key) => {
        var curConfig = currentSession.openid_config[key];
        $("#server_config").append("<b>"+key+"</b>:");
        if (key === "mtls_endpoint_aliases") {
          Object.keys(curConfig).forEach((mtls) => {
            $("#server_config").append("\n  <i><b>"+mtls+"</b></i>: "+curConfig[mtls]+"\n\n");
          });
        } else if (Array.isArray(curConfig)) {
          $("#server_config").append("\n  "+curConfig.join(" ")+"\n\n");
        } else {
          $("#server_config").append(" "+curConfig+"\n\n");
        }
      });
      
      $("#claims_config").empty();
      if (currentSession.openid_config.claims_supported) {
        $("#claims_config").append("<b>claims_supported</b>:\n  "+currentSession.openid_config.claims_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.claim_types_supported) {
        $("#claims_config").append("<b>claim_types_supported</b>:\n  "+currentSession.openid_config.claim_types_supported.join(", ")+"\n\n");
      }
      if (currentSession.openid_config.claims_parameter_supported) {
        $("#claims_config").append("<b>claims_parameter_supported</b>:\n  "+currentSession.openid_config.claims_parameter_supported+"\n\n");
      }
    }
    $("#response_type").val((currentSession.response_type.toString())||"");

    $("#scopeSupported").empty().append('<option></option>');
    if (currentSession.openid_config && currentSession.openid_config.scopes_supported) {
      currentSession.openid_config.scopes_supported.forEach((scope, index) => {
        if (!index && !$("#scope").val()) {
          $("#scope").val(scope.trim());
        }
        $("#scopeSupported").append('<option value="'+scope+'">'+ scope +'</option>');
      });
    }
    
    if (currentSession.auth_method & authMethodGet) {
      $("#auth_method_object").val("1");
    } else {
      $("#auth_method_object").val("2");
    }
    if (currentSession.auth_method & authMethodJwtSignSecret) {
      $("#auth_object_jwt_signed").val("1");
    } else if (currentSession.auth_method & authMethodJwtSignPrivkey) {
      $("#auth_object_jwt_signed").val("2");
    }
    if (currentSession.auth_method & authMethodJwtEncryptSecret) {
      $("#auth_object_jwt_encrypted").val("1");
    } else if (currentSession.auth_method & authMethodJwtEncryptPubkey) {
      $("#auth_object_jwt_encrypted").val("2");
    }
    if (!currentSession.token_method) {
      $("#token_method_object").val("0");
    } else if (currentSession.token_method & tokenMethodSecretBasic) {
      $("#token_method_object").val("1");
    } else if (currentSession.token_method & tokenMethodSecretPost) {
      $("#token_method_object").val("2");
    } else if (currentSession.token_method & tokenMethodTlsCertificate) {
      $("#token_method_object").val("3");
    } else if (currentSession.token_method & (tokenMethodJwtSignSecret|tokenMethodJwtSignPrivkey|tokenMethodJwtEncryptSecret|tokenMethodJwtEncryptPubkey)) {
      $("#token_method_object").val("4");
    }
    
    $("#device_auth_verification_uri_complete-qrcode").empty()
    if (currentSession.device_auth_verification_uri_complete) {
      var qr = qrcode(10, 'L');
      qr.addData(currentSession.device_auth_verification_uri_complete);
      qr.make();
      $("#device_auth_verification_uri_complete-qrcode").html('<a title="Click or scan to open link" href="'+currentSession.device_auth_verification_uri_complete+'">'+qr.createImgTag()+'</a>');
    }
    $("#device_auth_verification_uri-link").attr("href", (currentSession.device_auth_verification_uri||"#"));
    
    if (currentSession.claims) {
      $("#claims_payload").empty().html(JSON.stringify(currentSession.claims, null, 2));
    } else {
      $("#claims_payload").empty();
    }
    
    if (currentSession.authorization_details) {
      $("#rar_payload").empty().html(JSON.stringify(currentSession.authorization_details, null, 2));
    } else {
      $("#rar_payload").empty();
    }
    
    if (currentSession.access_token_payload) {
      $("#access_token_payload").empty().html(JSON.stringify(currentSession.access_token_payload, null, 2));
    }
    
    $("#additionalParameters").val("");
    Object.keys(currentSession.additional_parameters).forEach((param) => {
      var value = currentSession.additional_parameters[param];
      
      if (param === "display") {
        $("#additionalParametersDisplay").val(value);
      } else if (param === "prompt") {
        $("#additionalParametersPrompt").val(value);
      } else if (param === "ui_locales") {
        $("#additionalParametersUiLocales").val(value);
      } else {
        var addParam = $("#additionalParameters").val();
        if (addParam) {
          $("#additionalParameters").val(addParam+"\n"+param+":"+value);
        } else {
          $("#additionalParameters").val(param+":"+value);
        }
      }
    });
  }

  function saveSession() {
    $(".idwcc-session").each(function() {
      if ($(this).prop("id") === "response_type") {
        currentSession.response_type = parseInt($(this).val());
      } else if ($(this).prop("id") === "client_jwks") {
        try {
          currentSession.client_jwks = JSON.parse($(this).val());
        } catch (err) {
          delete(currentSession.client_jwks);
        }
      } else if ($(this).prop("id") === "server_jwks") {
        try {
          currentSession.server_jwks = JSON.parse($(this).val());
        } catch (err) {
          delete(currentSession.server_jwks);
        }
      } else if ($(this).prop("id") === "pkce_method") {
        currentSession.pkce_method = parseInt($("#pkce_method").val());
      } else {
        currentSession[$(this).prop("id")] = $(this).val();
      }
    });
    currentSession.auth_method = $("#auth_method_object").val()==="1"?authMethodGet:authMethodPost;
    var token_method_object = $("#token_method_object").val();
    currentSession.token_method = tokenMethodNone;
    if (token_method_object === "1") {
      currentSession.token_method = tokenMethodSecretBasic;
    } else if (token_method_object === "2") {
      currentSession.token_method |= tokenMethodSecretPost;
    } else if (token_method_object === "3") {
      currentSession.token_method |= tokenMethodTlsCertificate;
    }
    var auth_object_jwt_signed = $("#auth_object_jwt_signed").val();
    if (auth_object_jwt_signed === "1") {
      currentSession.auth_method |= authMethodJwtSignSecret;
      if (token_method_object === "4") {
        currentSession.token_method |= tokenMethodJwtSignSecret;
      }
    } else if (auth_object_jwt_signed === "2") {
      currentSession.auth_method |= authMethodJwtSignPrivkey;
      if (token_method_object === "4") {
        currentSession.token_method |= tokenMethodJwtSignPrivkey;
      }
    }
    var auth_object_jwt_encrypted = $("#auth_object_jwt_encrypted").val();
    if (auth_object_jwt_encrypted === "1") {
      currentSession.auth_method |= authMethodJwtEncryptSecret;
      if (token_method_object === "4") {
        currentSession.token_method |= tokenMethodJwtEncryptSecret;
      }
    } else if (auth_object_jwt_encrypted === "2") {
      currentSession.auth_method |= authMethodJwtEncryptPubkey;
      if (token_method_object === "4") {
        currentSession.token_method |= tokenMethodJwtEncryptPubkey;
      }
    }
    currentSession.remote_cert_flag = remoteVerifyNone;
    if ($("#remote_cert_flag-host-peer").prop("checked")) {
      currentSession.remote_cert_flag |= remoteHostVerifyPeer;
    }
    if ($("#remote_cert_flag-host-name").prop("checked")) {
      currentSession.remote_cert_flag |= remoteHostVerifyHostname;
    }
    if ($("#remote_cert_flag-proxy-peer").prop("checked")) {
      currentSession.remote_cert_flag |= remoteProxyVerifyPeer;
    }
    if ($("#remote_cert_flag-proxy-name").prop("checked")) {
      currentSession.remote_cert_flag |= remoteProxyVerifyHostname;
    }
    currentSession.decrypt_code = $("#decrypt_code").prop("checked");
    currentSession.decrypt_refresh_token = $("#decrypt_refresh_token").prop("checked");
    currentSession.decrypt_id_token = $("#decrypt_id_token").prop("checked");
    currentSession.decrypt_access_token = $("#decrypt_access_token").prop("checked");
    currentSession.use_dpop = $("#use_dpop").prop("checked");
    currentSession.openid_config_strict = $("#openid_config_strict").prop("checked");
    
    if ($("#additionalParameters").val()) {
      currentSession.additional_parameters = {};
      $("#additionalParameters").val().split("\n").forEach((param) => {
        if (param) {
          var vals = param.split(":");
          if (vals.length >= 2) {
            currentSession.additional_parameters[vals[0]] = vals[1];
          } else {
            currentSession.additional_parameters[vals[0]] = null;
          }
        }
      });
    }

    if ($("#additionalParametersDisplay").val()) {
      currentSession.additional_parameters.display = $("#additionalParametersDisplay").val();
    }

    if ($("#additionalParametersPrompt").val()) {
      currentSession.additional_parameters.prompt = $("#additionalParametersPrompt").val();
    }

    if ($("#additionalParametersUiLocales").val()) {
      currentSession.additional_parameters.ui_locales = $("#additionalParametersUiLocales").val();
    }

    return $.ajax({
      method: "POST",
      url: "/api/session",
      data: JSON.stringify(currentSession),
      contentType: "application/json; charset=utf-8"
    })
    .fail((error) => {
      showModal("Error saving session: "+error.responseText);
    });
  }

  function showModal(message) {
    $("#messageModalBody").empty().html(message);
    $("#messageModal").modal('show');
  }

  function prepareClientRegistration() {
    var parameters = {};
    try {
      if ($("#clientRegistrationAdditionalParameters").val()) {
        parameters = JSON.parse($("#clientRegistrationAdditionalParameters").val());
      }
      if ($("#clientRegistrationRedirectUri").val()) {
        if (parameters.redirect_uris) {
          parameters.redirect_uris.push($("#clientRegistrationRedirectUri").val());
        } else {
          parameters.redirect_uris = [$("#clientRegistrationRedirectUri").val()];
        }
      }
      if (!parameters.token_endpoint_auth_method) {
        parameters.token_endpoint_auth_method = $("#clientRegistrationAuthMethod").val();
      }
      if (!parameters.application_type) {
        parameters.application_type = $("#clientRegistrationAppType").val();
      }
      if (!parameters.grant_types) {
        parameters.grant_types = [];
      }
      if ($("#clientRegistrationGrantTypeAuthCode").prop("checked")) {
        parameters.grant_types.push("authorization_code");
      }
      if ($("#clientRegistrationGrantTypePassword").prop("checked")) {
        parameters.grant_types.push("password");
      }
      if ($("#clientRegistrationGrantTypeClientCredentials").prop("checked")) {
        parameters.grant_types.push("client_credentials");
      }
      if ($("#clientRegistrationGrantTypeRefreshToken").prop("checked")) {
        parameters.grant_types.push("refresh_token");
      }
      if ($("#clientRegistrationGrantTypeDeleteToken").prop("checked")) {
        parameters.grant_types.push("delete_token");
      }
      if ($("#clientRegistrationGrantTypeDeviceAuth").prop("checked")) {
        parameters.grant_types.push("device_authorization");
      }
      if (!parameters.response_types) {
        parameters.response_types = [];
      }
      if ($("#clientRegistrationResponseTypeCode").prop("checked")) {
        parameters.response_types.push("code");
      }
      if ($("#clientRegistrationResponseToken").prop("checked")) {
        parameters.response_types.push("token");
      }
      if ($("#clientRegistrationResponseTypeIdToken").prop("checked")) {
        parameters.response_types.push("id_token");
      }
    } catch(e) {
      showModal("Invalid parameters");
    }
    return parameters;
  }

  getSession();
});
