package com.getmyuri.user_auth_service.repository;

import com.getmyuri.user_auth_service.model.user.User;
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
public class FirebaseUserRepository {

    private static final String COLLECTION_NAME = "users";

    public Optional<User> findByEmail(String email) throws ExecutionException, InterruptedException {
        Firestore db = FirestoreClient.getFirestore();
        ApiFuture<QuerySnapshot> future = db.collection(COLLECTION_NAME).whereEqualTo("email", email).get();
        QuerySnapshot querySnapshot = future.get();
        if (!querySnapshot.isEmpty()) {
            QueryDocumentSnapshot document = querySnapshot.getDocuments().get(0);
            return Optional.of(document.toObject(User.class));
        }
        return Optional.empty();
    }

    public void save(User user) throws ExecutionException, InterruptedException {
        Firestore db = FirestoreClient.getFirestore();
        ApiFuture<WriteResult> future = db.collection(COLLECTION_NAME).document(user.getEmail()).set(user);
        future.get();
    }
}
