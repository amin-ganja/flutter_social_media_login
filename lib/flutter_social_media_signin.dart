library flutter_social_media_signin;

import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter_facebook_auth/flutter_facebook_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
import 'package:http/http.dart' as http;

class FlutterSocialMediaSignin {
  // Google Auth

  Future<OAuthCredential> signInWithGoogle() async {
    // Trigger the authentication flow
    final GoogleSignInAccount? googleUser = await GoogleSignIn().signIn();
    // Obtain the auth details from the request
    final GoogleSignInAuthentication? googleAuth =
    await googleUser?.authentication;
    // Create a new credential
    final credential = GoogleAuthProvider.credential(
        accessToken: googleAuth?.accessToken, idToken: googleAuth?.idToken);
    try {
      // Once signed in, return the OAuthCredential
      return credential;
    } catch (e) {
      throw Exception(e);
    }
  }

  // Facebook Auth

  Future<void> signInWithFacebook() async {
    dynamic userInfo;
    LoginResult result = await FacebookAuth.instance.login();
    if (result.status == LoginStatus.success) {
      final AccessToken accessToken = result.accessToken!;
      try {
        http.Response graphResponse = await http.get(Uri.parse(
            'https://graph.facebook.com/v2.12/me?fields=name,first_name,last_name,email,hometown,token_for_business&access_token=${accessToken
                .token}'));
        if (graphResponse.statusCode == 200) {
         userInfo = jsonDecode(graphResponse.body);
         return userInfo;
        } else {
          await FacebookAuth.instance.logOut();
        }
      }catch(e){
        throw Exception(e);
      }
    }
  }
// Apple Auth

  String generateNonce([int length = 32]) {
    const charset =
        '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._';
    final random = Random.secure();
    return List.generate(length, (_) => charset[random.nextInt(charset.length)])
        .join();
  }

  /// Returns the sha256 hash of [input] in hex notation.
  String sha256ofString(String input) {
    final bytes = utf8.encode(input);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  Future<OAuthCredential> signInWithApple(
      {required String clientID, required String redirectURL}) async {
    // To prevent replay attacks with the credential returned from Apple, we
    // include a nonce in the credential request. When signing in with
    // Firebase, the nonce in the id token returned by Apple, is expected to
    // match the sha256 hash of `rawNonce`.
    try {
      final rawNonce = generateNonce();
      final nonce = sha256ofString(rawNonce);

      // Request credential for the currently signed in Apple account.
      final appleCredential = await SignInWithApple.getAppleIDCredential(
        scopes: [
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ],
        webAuthenticationOptions: WebAuthenticationOptions(
            clientId: clientID, redirectUri: Uri.parse(redirectURL)),
        nonce: nonce,
      );
      // Create an `OAuthCredential` from the credential returned by Apple.
      final oauthCredential = OAuthProvider("apple.com").credential(
        idToken: appleCredential.identityToken,
        rawNonce: rawNonce,
      );
      // Sign in the user with Firebase. If the nonce we generated earlier does
      // not match the nonce in `appleCredential.identityToken`, sign in will fail.
      return oauthCredential;
    } on FirebaseAuthException catch (e) {
      throw Exception(e.message);
    }
  }

/*===============================================WebSocialLogin=============================================================*/

  //Google Auth
  Future<GoogleAuthProvider> signInWithGoogleWeb() async {
    // Create a new provider
    GoogleAuthProvider googleProvider = GoogleAuthProvider();
    googleProvider
        .addScope('https://www.googleapis.com/auth/contacts.readonly');
    googleProvider.setCustomParameters({'login_hint': 'user@example.com'});
    try {
      return googleProvider;
    } on FirebaseException catch (e) {
      throw Exception(e.message);
    }
  }

  //Facebook Auth

  Future<FacebookAuthProvider> signInWithFacebookWeb() async {
    // Create a new provider
    FacebookAuthProvider facebookProvider = FacebookAuthProvider();

    facebookProvider.addScope('emailq ');
    facebookProvider.setCustomParameters({
      'display': 'popup',
    });
    // Once signed in, return the UserCredential
    try {
      return facebookProvider;
    } on FirebaseException catch (e) {
      throw Exception(e.message);
    }
  }


  //Apple Auth

  Future<OAuthProvider> signInWithAppleWeb() async {
    // Create and configure an OAuthProvider for Sign In with Apple.
    final provider = OAuthProvider("apple.com")
      ..addScope('email')..addScope('name');

    // Sign in the user with Firebase.
    try {
      return provider;
    } on FirebaseException catch (e) {
      throw Exception(e.message);
    }
  }


  /*===============================================SignOut=============================================================*/


  //Google SignOut
  Future<GoogleSignInAccount?> googleSignOut() async {
    try {
      return await GoogleSignIn().signOut();
    } on FirebaseException catch (e) {
      throw Exception(e.message);
    }
  }

  //Facebook SignOut
  Future<void> faceBookSignOut() async {
    try {
     return await FacebookAuth.instance.logOut();
    } catch (e) {
      throw Exception(e);
    }
  }
}


