library flutter_social_media_signin;

import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter_facebook_auth/flutter_facebook_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

class FlutterSocialMediaSignin {
  // Google Auth

  Future<UserCredential> signInWithGoogle() async {
    // Trigger the authentication flow
    final GoogleSignInAccount? googleUser = await GoogleSignIn().signIn();
    // Obtain the auth details from the request
    final GoogleSignInAuthentication? googleAuth =
        await googleUser?.authentication;
    // Create a new credential
    final credential = GoogleAuthProvider.credential(
        accessToken: googleAuth?.accessToken, idToken: googleAuth?.idToken);
    try {
      // Once signed in, return the UserCredential
      return await FirebaseAuth.instance.signInWithCredential(credential);
    } on FirebaseAuthException catch (e) {
      throw Exception(e.message);
    }
  }

  // Facebook Auth

  Future<UserCredential> signInWithFacebook() async {
    // Trigger the sign-in flow
    final LoginResult loginResult = await FacebookAuth.instance.login(
    permissions: ['public_profile','email']
    );

    // Create a credential from the access token
    final OAuthCredential facebookAuthCredential =
        FacebookAuthProvider.credential(loginResult.accessToken!.token);

    // Once signed in, return the UserCredential
    try {
      return FirebaseAuth.instance.signInWithCredential(facebookAuthCredential);
    } on FirebaseAuthException catch (e) {
      throw Exception(e.message);
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

  Future<UserCredential> signInWithApple(
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

      return FirebaseAuth.instance.signInWithCredential(oauthCredential);
    } on FirebaseAuthException catch (e) {
      throw Exception(e.message);
    }
  }

/*===============================================WebSocialLogin=============================================================*/

  //Google Auth
  Future<UserCredential> signInWithGoogleWeb() async {
    // Create a new provider
    GoogleAuthProvider googleProvider = GoogleAuthProvider();
    googleProvider
        .addScope('https://www.googleapis.com/auth/contacts.readonly');
    googleProvider.setCustomParameters({'login_hint': 'user@example.com'});
    try {
      return await FirebaseAuth.instance.signInWithPopup(googleProvider);
    } on FirebaseException catch (e) {
      throw Exception(e.message);
    }
  }

  //Facebook Auth

  Future<UserCredential> signInWithFacebookWeb() async {
    // Create a new provider
    FacebookAuthProvider facebookProvider = FacebookAuthProvider();

    facebookProvider.addScope('emailq ');
    facebookProvider.setCustomParameters({
      'display': 'popup',
    });

    // Once signed in, return the UserCredential
    try {
      return await FirebaseAuth.instance.signInWithPopup(facebookProvider);
    } on FirebaseException catch (e) {
      throw Exception(e.message);
    }

  }

  //Apple Auth

  Future<UserCredential> signInWithAppleWeb() async {
    // Create and configure an OAuthProvider for Sign In with Apple.
    final provider = OAuthProvider("apple.com")
      ..addScope('email')
      ..addScope('name');

    // Sign in the user with Firebase.
    try {
      return await FirebaseAuth.instance.signInWithPopup(provider);
    } on FirebaseException catch (e) {
      throw Exception(e.message);
    }
  }
}
