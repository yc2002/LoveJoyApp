package com.example.demo.request;


import com.example.demo.appuser.AppUser;
import com.example.demo.security.config.SecureDetailGenerator;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.Type;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.persistence.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@Entity
public class EvaluationRequest {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    @Type(type = "text")
    private String note;

    @Column(nullable = false)
    private String contact;

    @Column(nullable = false)
    private Boolean open = true;

    @Column(nullable = true, length = 64)
    private String photos;

    @ManyToOne(cascade = CascadeType.MERGE)
    @JoinColumn(
            nullable = false,
            name = "app_user_id"
    )
    private AppUser appUser;


    public EvaluationRequest(String contact,
                            String note,
                            AppUser appUser,
                             String photos) {
        this.note = note;
        this.contact = contact;
        this.appUser = appUser;
        this.photos = photos;
    }

    @Transient
    public String getPhotosImagePath() {
        return "/request-photos/" + id + "/" + photos;
    }

}
