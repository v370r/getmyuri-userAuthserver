package com.getmyuri.user_auth_service.repository;

import com.getmyuri.user_auth_service.model.role.Role;
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
public class FirebaseRoleRepository {

    private static final String COLLECTION_NAME = "roles";

    public Optional<Role> findByName(String name) throws ExecutionException, InterruptedException {
        Firestore db = FirestoreClient.getFirestore();
        ApiFuture<QuerySnapshot> future = db.collection(COLLECTION_NAME).whereEqualTo("name", name).get();
        QuerySnapshot querySnapshot = future.get();
        if (!querySnapshot.isEmpty()) {
            QueryDocumentSnapshot document = querySnapshot.getDocuments().get(0);
            return Optional.of(document.toObject(Role.class));
        }
        return Optional.empty();
    }

    public void save(Role role) throws ExecutionException, InterruptedException {
        Firestore db = FirestoreClient.getFirestore();
        ApiFuture<WriteResult> future = db.collection(COLLECTION_NAME).document(role.getName()).set(role);
        future.get();
    }
}
