package com.getmyuri.user_auth_service.repository;

import com.getmyuri.user_auth_service.model.user.Token;
import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.cloud.firestore.QuerySnapshot;
import com.google.cloud.firestore.WriteResult;
import com.google.firebase.cloud.FirestoreClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.ExecutionException;

@Repository
public class FirebaseTokenRepository {

    private static final String COLLECTION_NAME = "tokens";

    public Optional<Token> findByToken(String token) throws ExecutionException, InterruptedException {
        Firestore db = FirestoreClient.getFirestore();
        ApiFuture<QuerySnapshot> future = db.collection(COLLECTION_NAME).whereEqualTo("token", token).get();
        QuerySnapshot querySnapshot = future.get();
        if (!querySnapshot.isEmpty()) {
            QueryDocumentSnapshot document = querySnapshot.getDocuments().get(0);
            return Optional.of(document.toObject(Token.class));
        }
        return Optional.empty();
    }

    public void save(Token token) throws ExecutionException, InterruptedException {
        Firestore db = FirestoreClient.getFirestore();
        ApiFuture<WriteResult> future = db.collection(COLLECTION_NAME).document(token.getToken()).set(token);
        future.get();
    }
}
