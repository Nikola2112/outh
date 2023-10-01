package com.goit.entity.pk;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Embeddable
public class UserRolePK implements Serializable {

	@Serial
	private static final long serialVersionUID = 1L;

	@Column(name = "USER_ID")
	private Long userId;

	@Column(name = "ROLE_ID")
	private Long roleId;


	@Override
	public int hashCode() {
		return Objects.hash(roleId, userId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		UserRolePK other = (UserRolePK) obj;
		return Objects.equals(roleId, other.roleId) && Objects.equals(userId, other.userId);
	}

}
